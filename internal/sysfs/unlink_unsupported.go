//go:build !(unix || windows)

package sysfs

import (
	"os"

	"github.com/ChrisRx/wazero/experimental/sys"
)

func unlink(name string) sys.Errno {
	err := os.Remove(name)
	return sys.UnwrapOSError(err)
}
