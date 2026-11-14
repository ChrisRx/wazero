//go:build !(linux || darwin)

package sysfs

import experimentalsys "github.com/ChrisRx/wazero/experimental/sys"

// PollHostSupported reports whether PollHost is available.
const PollHostSupported = false

// PollHost is not supported on this platform.
func PollHost([]PollRequest, int32) experimentalsys.Errno {
	return experimentalsys.ENOSYS
}
