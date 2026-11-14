package sysfs

import (
	"math"
	"time"

	experimentalsys "github.com/ChrisRx/wazero/experimental/sys"
)

// PollRequest is a host file descriptor to wait on with PollHost.
type PollRequest struct {
	// Fd is the host file descriptor, from HostFd.
	Fd uintptr
	// Flag is the events to wait for: POLLIN, POLLOUT or both.
	Flag experimentalsys.Pflag
	// Ready is set by PollHost when one of the events, an error or a hang
	// up happened.
	Ready bool
}

// hostFile is implemented by files backed by a host file descriptor.
type hostFile interface {
	hostFd() (uintptr, bool)
}

// HostFd returns the host file descriptor backing f, for PollHost.
func HostFd(f experimentalsys.File) (uintptr, bool) {
	if h, ok := f.(hostFile); ok {
		return h.hostFd()
	}
	return 0, false
}

// TimeoutMillis converts a timeout to the milliseconds PollHost and
// experimentalsys.Pollable take, rounding up. A negative timeout waits
// forever.
func TimeoutMillis(d time.Duration) int32 {
	switch {
	case d < 0:
		return -1
	case d >= math.MaxInt32*time.Millisecond:
		return math.MaxInt32
	}
	return int32((d + time.Millisecond - 1) / time.Millisecond)
}
