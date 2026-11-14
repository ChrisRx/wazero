package wasi_snapshot_preview1

import (
	"context"
	"errors"
	"time"

	"github.com/ChrisRx/wazero/api"
	experimentalsys "github.com/ChrisRx/wazero/experimental/sys"
	"github.com/ChrisRx/wazero/internal/sysfs"
	"github.com/ChrisRx/wazero/sys"
)

// contextCheckInterval bounds how long a blocking function waits without
// checking whether its context is done.
const contextCheckInterval = 100 * time.Millisecond

// exitIfDone exits the module when ctx is done, like proc_exit, with the
// exit code RuntimeConfig.WithCloseOnContextDone uses. Functions that block
// call it while waiting, so a guest waiting for I/O or sleeping stops when
// its context is canceled even without WithCloseOnContextDone, which
// interrupts running code at a cost.
func exitIfDone(ctx context.Context, mod api.Module) {
	err := ctx.Err()
	if err == nil {
		return
	}
	code := sys.ExitCodeContextCanceled
	if errors.Is(err, context.DeadlineExceeded) {
		code = sys.ExitCodeDeadlineExceeded
	}
	_ = mod.CloseWithExitCode(ctx, code)
	panic(sys.NewExitError(code))
}

// pollHostContext is sysfs.PollHost, exiting the module when ctx is done.
func pollHostContext(ctx context.Context, mod api.Module, reqs []sysfs.PollRequest, timeoutMillis int32) experimentalsys.Errno {
	if ctx.Done() == nil {
		return sysfs.PollHost(reqs, timeoutMillis)
	}
	deadline := time.Now().Add(time.Duration(timeoutMillis) * time.Millisecond)
	for {
		wait := contextCheckInterval
		if timeoutMillis >= 0 {
			wait = min(wait, max(0, time.Until(deadline)))
		}
		if errno := sysfs.PollHost(reqs, sysfs.TimeoutMillis(wait)); errno != 0 {
			return errno
		}
		for _, r := range reqs {
			if r.Ready {
				return 0
			}
		}
		exitIfDone(ctx, mod)
		if timeoutMillis >= 0 && !time.Now().Before(deadline) {
			return 0
		}
	}
}

// sleepContext sleeps for d with nanosleep, exiting the module when ctx is
// done.
func sleepContext(ctx context.Context, mod api.Module, nanosleep func(int64), d time.Duration) {
	if ctx.Done() == nil {
		nanosleep(int64(d))
		return
	}
	for d > 0 {
		step := min(d, contextCheckInterval)
		nanosleep(int64(step))
		d -= step
		exitIfDone(ctx, mod)
	}
}

// waitSocket waits until the socket f is ready for flag if it is in
// blocking mode, so that the blocking call that follows doesn't wait past
// ctx being done.
func waitSocket(ctx context.Context, mod api.Module, f experimentalsys.File, flag experimentalsys.Pflag) {
	if ctx.Done() == nil || isNonblock(f) {
		return
	}
	fd, ok := sysfs.HostFd(f)
	if !ok {
		return
	}
	_ = pollHostContext(ctx, mod, []sysfs.PollRequest{{Fd: fd, Flag: flag}}, -1)
}
