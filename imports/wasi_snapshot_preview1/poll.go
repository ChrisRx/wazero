package wasi_snapshot_preview1

import (
	"context"
	"time"

	"github.com/ChrisRx/wazero/api"
	"github.com/ChrisRx/wazero/experimental/sys"
	socketapi "github.com/ChrisRx/wazero/internal/sock"
	internalsys "github.com/ChrisRx/wazero/internal/sys"
	"github.com/ChrisRx/wazero/internal/sysfs"
	"github.com/ChrisRx/wazero/internal/wasip1"
	"github.com/ChrisRx/wazero/internal/wasm"
)

// pollOneoff is the WASI function named PollOneoffName that concurrently
// polls for the occurrence of a set of events.
//
// # Parameters
//
//   - in: pointer to the subscriptions (48 bytes each)
//   - out: pointer to the resulting events (32 bytes each)
//   - nsubscriptions: count of subscriptions, zero returns sys.EINVAL.
//   - resultNevents: count of events.
//
// Result (Errno)
//
// The return value is 0 except the following error conditions:
//   - sys.EINVAL: the parameters are invalid
//   - sys.ENOTSUP: a parameters is valid, but not yet supported.
//   - sys.EFAULT: there is not enough memory to read the subscriptions or
//     write results.
//
// # Notes
//
//   - Since the `out` pointer nests Errno, the result is always 0.
//   - This is similar to `poll` in POSIX.
//
// See https://github.com/WebAssembly/WASI/blob/snapshot-01/phases/snapshot/docs.md#poll_oneoff
// See https://linux.die.net/man/3/poll
var pollOneoff = newHostFunc(
	wasip1.PollOneoffName, pollOneoffFn,
	[]wasm.ValueType{i32, i32, i32, i32},
	"in", "out", "nsubscriptions", "result.nevents",
)

type event struct {
	eventType byte
	userData  []byte
	errno     wasip1.Errno
}

func pollOneoffFn(ctx context.Context, mod api.Module, params []uint64) sys.Errno {
	in := uint32(params[0])
	out := uint32(params[1])
	nsubscriptions := uint32(params[2])
	resultNevents := uint32(params[3])

	if nsubscriptions == 0 {
		return sys.EINVAL
	}

	mem := mod.Memory()

	// Ensure capacity prior to the read loop to reduce error handling.
	inBuf, ok := mem.Read(in, nsubscriptions*48)
	if !ok {
		return sys.EFAULT
	}
	outBuf, ok := mem.Read(out, nsubscriptions*32)
	// zero-out all buffer before writing
	clear(outBuf)

	if !ok {
		return sys.EFAULT
	}

	// Eagerly write the number of events which will equal subscriptions unless
	// there's a fault in parsing (not processing).
	if !mod.Memory().WriteUint32Le(resultNevents, nsubscriptions) {
		return sys.EFAULT
	}

	// Loop through all subscriptions and write their output.

	// Extract FS context, used in the body of the for loop for FS access.
	fsc := mod.(*wasm.ModuleInstance).Sys.FS()
	// blockingPollSubs are fd subscriptions processed after the loop via polling.
	var blockingPollSubs []pollSub
	// readyFds counts fd subscriptions already acked in the loop, which
	// means the blocking ones are only checked, not waited for.
	readyFds := 0
	// The timeout is initialized at max Duration, the loop will find the minimum.
	const noTimeout = time.Duration(1<<63 - 1)
	timeout := noTimeout
	// Count of all the subscriptions that have been already written back to outBuf.
	// nevents*32 returns at all times the offset where the next event should be written:
	// this way we ensure that there are no gaps between records.
	nevents := uint32(0)

	// Layout is subscription_u: Union
	// https://github.com/WebAssembly/WASI/blob/snapshot-01/phases/snapshot/docs.md#subscription_u
	for i := uint32(0); i < nsubscriptions; i++ {
		inOffset := i * 48
		outOffset := nevents * 32

		eventType := inBuf[inOffset+8] // +8 past userdata
		// +8 past userdata +8 contents_offset
		argBuf := inBuf[inOffset+8+8:]
		userData := inBuf[inOffset : inOffset+8]

		evt := &event{
			eventType: eventType,
			userData:  userData,
			errno:     wasip1.ErrnoSuccess,
		}

		switch eventType {
		case wasip1.EventTypeClock: // handle later
			newTimeout, err := processClockEvent(argBuf)
			if err != 0 {
				return err
			}
			// Min timeout.
			if newTimeout < timeout {
				timeout = newTimeout
			}
			// Ack the clock event to the outBuf.
			writeEvent(outBuf[outOffset:], evt)
			nevents++
		case wasip1.EventTypeFdRead:
			fd := int32(le.Uint32(argBuf))
			if fd < 0 {
				return sys.EBADF
			}
			if file, ok := fsc.LookupFile(fd); !ok {
				evt.errno = wasip1.ErrnoBadf
				writeEvent(outBuf[outOffset:], evt)
				nevents++
				readyFds++
			} else if fd != internalsys.FdStdin && isNonblock(file.File) && !isSocket(file.File) {
				writeEvent(outBuf[outOffset:], evt)
				nevents++
				readyFds++
			} else {
				// The fd is in blocking mode, or a socket whose readiness
				// is known; do not ack yet, append to a slice for deferred
				// polling evaluation.
				blockingPollSubs = append(blockingPollSubs, pollSub{evt, file.File, sys.POLLIN})
			}
		case wasip1.EventTypeFdWrite:
			fd := int32(le.Uint32(argBuf))
			if fd < 0 {
				return sys.EBADF
			}
			if file, ok := fsc.LookupFile(fd); ok && isSocket(file.File) {
				blockingPollSubs = append(blockingPollSubs, pollSub{evt, file.File, sys.POLLOUT})
				continue
			} else if ok {
				evt.errno = wasip1.ErrnoNotsup
			} else {
				evt.errno = wasip1.ErrnoBadf
			}
			nevents++
			readyFds++
			writeEvent(outBuf[outOffset:], evt)
		default:
			return sys.EINVAL
		}
	}

	sysCtx := mod.(*wasm.ModuleInstance).Sys
	if nevents == nsubscriptions {
		// We already wrote back all the results. We already wrote this number
		// earlier to offset `resultNevents`.
		// We only need to observe the timeout (lowered only by clock subscriptions)
		// and return.
		if timeout != noTimeout && timeout > 0 {
			sleepContext(ctx, mod, sysCtx.Nanosleep, timeout)
		}
		return 0
	}

	if readyFds > 0 {
		timeout = 0
	}

	// When every blocking subscriber has a host file descriptor, wait for
	// all of them at once.
	if done, errno := pollHost(ctx, mod, blockingPollSubs, timeout, outBuf, &nevents); errno != 0 {
		return errno
	} else if done {
		blockingPollSubs = nil
	}

	// Wait for the timeout to expire, or for data to become available on
	// each blocking fd subscriber. The remaining time budget is tracked
	// across iterations so total wall time never exceeds the timeout.
	remaining := timeout
	for _, sub := range blockingPollSubs {
		p, ok := sub.file.(sys.Pollable)
		if !ok {
			sub.evt.errno = wasip1.ErrnoNotsup
			writeEvent(outBuf[nevents*32:], sub.evt)
			nevents++
			continue
		}
		start := time.Now()
		if remaining == noTimeout {
			remaining = -1
		}
		ready, errno := p.Poll(sub.flag, sysfs.TimeoutMillis(remaining))
		switch errno {
		case 0:
			if ready {
				sub.evt.errno = 0
				writeEvent(outBuf[nevents*32:], sub.evt)
				nevents++
			}
		case sys.ENOSYS, sys.ENOTSUP:
			sub.evt.errno = wasip1.ErrnoNotsup
			writeEvent(outBuf[nevents*32:], sub.evt)
			nevents++
		default:
			return errno
		}
		if remaining < 0 {
			continue
		}
		if elapsed := time.Since(start); elapsed < remaining {
			remaining -= elapsed
		} else {
			remaining = 0
		}
	}

	if nevents != nsubscriptions {
		if !mod.Memory().WriteUint32Le(resultNevents, nevents) {
			return sys.EFAULT
		}
	}

	return 0
}

// pollSub is an fd subscription that is waited for.
type pollSub struct {
	evt  *event
	file sys.File
	flag sys.Pflag
}

// pollHost waits for subs together, and acks the ready ones, when all have a
// host file descriptor. Otherwise it returns false and leaves them be.
func pollHost(ctx context.Context, mod api.Module, subs []pollSub, timeout time.Duration, outBuf []byte, nevents *uint32) (bool, sys.Errno) {
	if !sysfs.PollHostSupported || len(subs) == 0 {
		return false, 0
	}
	reqs := make([]sysfs.PollRequest, len(subs))
	for i, sub := range subs {
		fd, ok := sysfs.HostFd(sub.file)
		if !ok {
			return false, 0
		}
		reqs[i] = sysfs.PollRequest{Fd: fd, Flag: sub.flag}
	}
	if timeout == time.Duration(1<<63-1) {
		timeout = -1
	}
	if errno := pollHostContext(ctx, mod, reqs, sysfs.TimeoutMillis(timeout)); errno != 0 {
		return false, errno
	}
	for i, sub := range subs {
		if reqs[i].Ready {
			writeEvent(outBuf[*nevents*32:], sub.evt)
			*nevents++
		}
	}
	return true, 0
}

// isSocket reports whether f is a TCP socket, whose readiness is polled
// even in non-blocking mode.
func isSocket(f sys.File) bool {
	switch f.(type) {
	case socketapi.TCPSock, socketapi.TCPConn:
		return true
	}
	return false
}

// processClockEvent supports only relative name events, as that's what's used
// to implement sleep in various compilers including Rust, Zig and TinyGo.
func processClockEvent(inBuf []byte) (time.Duration, sys.Errno) {
	_ /* ID */ = le.Uint32(inBuf[0:8])          // See below
	timeout := le.Uint64(inBuf[8:16])           // nanos if relative
	_ /* precision */ = le.Uint64(inBuf[16:24]) // Unused
	flags := le.Uint16(inBuf[24:32])

	var err sys.Errno
	// subclockflags has only one flag defined:  subscription_clock_abstime
	switch flags {
	case 0: // relative time
	case 1: // subscription_clock_abstime
		err = sys.ENOTSUP
	default: // subclockflags has only one flag defined.
		err = sys.EINVAL
	}

	if err != 0 {
		return 0, err
	} else {
		// https://linux.die.net/man/3/clock_settime says relative timers are
		// unaffected. Since this function only supports relative timeout, we can
		// skip name ID validation and use a single sleep function.

		return time.Duration(timeout), 0
	}
}

// isNonblock returns true if the file implements PollableFile and is in
// non-blocking mode.
func isNonblock(f sys.File) bool {
	if pf, ok := f.(sys.PollableFile); ok {
		return pf.IsNonblock()
	}
	return false
}

// writeEvent writes the event corresponding to the processed subscription.
// https://github.com/WebAssembly/WASI/blob/snapshot-01/phases/snapshot/docs.md#-event-struct
func writeEvent(outBuf []byte, evt *event) {
	copy(outBuf, evt.userData)  // userdata
	outBuf[8] = byte(evt.errno) // uint16, but safe as < 255
	outBuf[9] = 0
	le.PutUint32(outBuf[10:], uint32(evt.eventType))
	// TODO: When FD events are supported, write outOffset+16
}
