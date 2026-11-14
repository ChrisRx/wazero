package sock

import (
	"errors"
	"fmt"
	"net"

	"github.com/ChrisRx/wazero/api"
	experimentalsys "github.com/ChrisRx/wazero/experimental/sys"
	internalsys "github.com/ChrisRx/wazero/internal/sys"
	"github.com/ChrisRx/wazero/internal/sysfs"
	"github.com/ChrisRx/wazero/internal/wasm"
)

// Open adds f to the file descriptor table of mod and returns its
// descriptor. It is meant for a socket that isn't bound or connected yet,
// which host functions later turn into a listener or connection with
// Attach. Closing the descriptor closes f. For fd_fdstat_set_flags to set
// non-blocking mode, f must implement experimentalsys.PollableFile.
//
// mod must be the module a host function was called with.
func Open(mod api.Module, f experimentalsys.File) (int32, error) {
	fsc, err := fsContext(mod)
	if err != nil {
		return 0, err
	}
	fd, errno := fsc.InsertFile(f)
	if errno != 0 {
		return 0, errno
	}
	return fd, nil
}

// Attach makes the file descriptor fd of mod refer to conn, a
// *net.TCPListener or *net.TCPConn, which the guest can then use with
// sock_accept, sock_recv, sock_send, sock_shutdown and poll_oneoff. The file
// fd referred to is dropped without being closed, and if it was in
// non-blocking mode, conn is too. Closing the descriptor closes conn.
func Attach(mod api.Module, fd int32, conn any) error {
	fsc, err := fsContext(mod)
	if err != nil {
		return err
	}
	var f experimentalsys.File
	switch c := conn.(type) {
	case *net.TCPListener:
		f = sysfs.NewTCPListenerFile(c)
	case *net.TCPConn:
		f = sysfs.NewTCPConnFile(c)
	default:
		return fmt.Errorf("unsupported socket type %T", conn)
	}
	e, ok := fsc.LookupFile(fd)
	if !ok {
		return experimentalsys.EBADF
	}
	if pf, ok := e.File.(experimentalsys.PollableFile); ok && pf.IsNonblock() {
		if errno := f.(experimentalsys.PollableFile).SetNonblock(true); errno != 0 {
			return errno
		}
	}
	if errno := fsc.ReplaceFile(fd, f); errno != 0 {
		return errno
	}
	return nil
}

// Lookup returns what the file descriptor fd of mod refers to: the
// *net.TCPListener or *net.TCPConn of a TCP socket, or else the
// experimentalsys.File, such as one given to Open.
func Lookup(mod api.Module, fd int32) (any, bool) {
	fsc, err := fsContext(mod)
	if err != nil {
		return nil, false
	}
	e, ok := fsc.LookupFile(fd)
	if !ok {
		return nil, false
	}
	if conn, ok := sysfs.SockConn(e.File); ok {
		return conn, true
	}
	return e.File, true
}

func fsContext(mod api.Module) (*internalsys.FSContext, error) {
	m, ok := mod.(*wasm.ModuleInstance)
	if !ok || m.Sys == nil {
		return nil, errors.New("not a module instance with system access")
	}
	return m.Sys.FS(), nil
}
