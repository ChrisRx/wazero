//go:build linux || darwin

package sysfs

import (
	"time"

	experimentalsys "github.com/ChrisRx/wazero/experimental/sys"
)

const (
	_POLLOUT = 0x0004
)

// PollHostSupported reports whether PollHost is available.
const PollHostSupported = true

// PollHost waits until at least one of reqs is ready, or timeoutMillis
// passes (negative waits forever, zero doesn't wait), and sets Ready on
// those that are.
func PollHost(reqs []PollRequest, timeoutMillis int32) experimentalsys.Errno {
	fds := make([]pollFd, len(reqs))
	for i, r := range reqs {
		var events int16
		if r.Flag&experimentalsys.POLLIN != 0 {
			events |= _POLLIN
		}
		if r.Flag&experimentalsys.POLLOUT != 0 {
			events |= _POLLOUT
		}
		fds[i] = newPollFd(r.Fd, events, 0)
	}
	deadline := time.Now().Add(time.Duration(timeoutMillis) * time.Millisecond)
	for {
		n, errno := _poll(fds, timeoutMillis)
		if errno == experimentalsys.EINTR {
			// Go preempts goroutines with signals, so retry with what's
			// left of the timeout.
			if timeoutMillis > 0 {
				timeoutMillis = TimeoutMillis(max(0, time.Until(deadline)))
			}
			continue
		}
		if errno != 0 {
			return errno
		}
		if n > 0 {
			for i := range fds {
				reqs[i].Ready = fds[i].revents != 0
			}
		}
		return 0
	}
}
