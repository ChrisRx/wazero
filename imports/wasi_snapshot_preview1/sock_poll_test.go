package wasi_snapshot_preview1_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ChrisRx/wazero"
	"github.com/ChrisRx/wazero/api"
	experimentalsock "github.com/ChrisRx/wazero/experimental/sock"
	experimentalsys "github.com/ChrisRx/wazero/experimental/sys"
	"github.com/ChrisRx/wazero/internal/sys"
	"github.com/ChrisRx/wazero/internal/testing/require"
	"github.com/ChrisRx/wazero/internal/wasip1"
)

// pollSub is a poll_oneoff subscription: an fd read or write, or a relative
// clock timeout.
type pollSub struct {
	userData  uint64
	eventType byte
	fd        uint32
	timeout   time.Duration
}

// pollSockets calls poll_oneoff with subs and returns the user data of the
// fd events that were ready, and how long it took.
func pollSockets(t *testing.T, mod api.Module, subs ...pollSub) ([]uint64, time.Duration) {
	t.Helper()
	const in, out, resultNevents = 0, 1024, 2048
	buf := make([]byte, 48*len(subs))
	for i, s := range subs {
		b := buf[i*48:]
		binary.LittleEndian.PutUint64(b, s.userData)
		b[8] = s.eventType
		if s.eventType == wasip1.EventTypeClock {
			binary.LittleEndian.PutUint64(b[24:], uint64(s.timeout))
		} else {
			binary.LittleEndian.PutUint32(b[16:], s.fd)
		}
	}
	require.True(t, mod.Memory().Write(in, buf))
	start := time.Now()
	requireErrnoResult(t, wasip1.ErrnoSuccess, mod, wasip1.PollOneoffName, in, out, uint64(len(subs)), resultNevents)
	elapsed := time.Since(start)
	nevents, _ := mod.Memory().ReadUint32Le(resultNevents)
	var ready []uint64
	for i := uint32(0); i < nevents; i++ {
		evt, _ := mod.Memory().Read(out+i*32, 32)
		if evt[10] != wasip1.EventTypeClock {
			require.Equal(t, uint16(0), binary.LittleEndian.Uint16(evt[8:]), "errno of event %d", i)
			ready = append(ready, binary.LittleEndian.Uint64(evt))
		}
	}
	return ready, elapsed
}

func Test_pollOneoff_sockets(t *testing.T) {
	ctx := experimentalsock.WithConfig(testCtx, experimentalsock.NewConfig().WithTCPListener("127.0.0.1", 0))
	mod, r, _ := requireProxyModuleWithContext(ctx, t, wazero.NewModuleConfig())
	defer r.Close(testCtx)
	listener := uint32(sys.FdPreopen)
	clock := func(d time.Duration) pollSub {
		return pollSub{userData: 99, eventType: wasip1.EventTypeClock, timeout: d}
	}
	read := func(fd uint32) pollSub {
		return pollSub{userData: uint64(fd), eventType: wasip1.EventTypeFdRead, fd: fd}
	}
	write := func(fd uint32) pollSub {
		return pollSub{userData: uint64(fd) + 100, eventType: wasip1.EventTypeFdWrite, fd: fd}
	}

	// Non-blocking, as in a guest with a socket timeout. Not ready until a
	// connection comes.
	requireErrnoResult(t, wasip1.ErrnoSuccess, mod, wasip1.FdFdstatSetFlagsName, uint64(listener), uint64(wasip1.FD_NONBLOCK))
	ready, elapsed := pollSockets(t, mod, read(listener), clock(50*time.Millisecond))
	require.Equal(t, 0, len(ready))
	require.True(t, elapsed >= 50*time.Millisecond, "returned after %v", elapsed)

	// A connection makes it readable, without waiting out the timeout.
	client, err := net.DialTCP("tcp", nil, requireTCPListenerAddr(t, mod))
	require.NoError(t, err)
	defer client.Close() //nolint
	ready, elapsed = pollSockets(t, mod, read(listener), clock(10*time.Second))
	require.Equal(t, []uint64{uint64(listener)}, ready)
	require.True(t, elapsed < 5*time.Second, "returned after %v", elapsed)

	requireErrnoResult(t, wasip1.ErrnoSuccess, mod, wasip1.SockAcceptName, uint64(listener), 0, 128)
	conn, _ := mod.Memory().ReadUint32Le(128)

	// Writable right away, readable once the client writes. Several
	// descriptors are waited for together, without a timeout.
	ready, _ = pollSockets(t, mod, read(conn), write(conn))
	require.Equal(t, []uint64{uint64(conn) + 100}, ready)
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = client.Write([]byte("hi"))
	}()
	ready, elapsed = pollSockets(t, mod, read(listener), read(conn))
	require.Equal(t, []uint64{uint64(conn)}, ready)
	require.True(t, elapsed >= 40*time.Millisecond, "returned after %v", elapsed)

	// Closing the descriptor closes the connection: the client sees EOF.
	require.True(t, mod.Memory().WriteUint32Le(256, 512))
	require.True(t, mod.Memory().WriteUint32Le(260, 16))
	requireErrnoResult(t, wasip1.ErrnoSuccess, mod, wasip1.SockRecvName, uint64(conn), 256, 1, 0, 264, 268)
	n, _ := mod.Memory().ReadUint32Le(264)
	require.Equal(t, uint32(2), n)
	requireErrnoResult(t, wasip1.ErrnoSuccess, mod, wasip1.FdCloseName, uint64(conn))
	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = io.ReadAll(client)
	require.NoError(t, err)
}

// pendingSocket stands in for a socket that isn't bound or connected yet.
type pendingSocket struct {
	experimentalsys.UnimplementedFile
	nonblock, closed bool
}

func (f *pendingSocket) IsNonblock() bool { return f.nonblock }

func (f *pendingSocket) SetNonblock(enable bool) experimentalsys.Errno {
	f.nonblock = enable
	return 0
}

func (f *pendingSocket) Poll(experimentalsys.Pflag, int32) (bool, experimentalsys.Errno) {
	return false, experimentalsys.ENOTSUP
}

func (f *pendingSocket) Close() experimentalsys.Errno {
	f.closed = true
	return 0
}

func Test_sockOpenAttach(t *testing.T) {
	mod, r, _ := requireProxyModule(t, wazero.NewModuleConfig())
	defer r.Close(testCtx)

	pending := &pendingSocket{nonblock: true}
	fd, err := experimentalsock.Open(mod, pending)
	require.NoError(t, err)
	got, ok := experimentalsock.Lookup(mod, fd)
	require.True(t, ok)
	require.Equal(t, experimentalsys.File(pending), got)

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	require.NoError(t, experimentalsock.Attach(mod, fd, ln))
	got, ok = experimentalsock.Lookup(mod, fd)
	require.True(t, ok)
	require.Equal(t, any(ln), got)
	require.False(t, pending.closed)

	// Accepting works on it, and kept the non-blocking mode.
	requireErrnoResult(t, wasip1.ErrnoAgain, mod, wasip1.SockAcceptName, uint64(fd), 0, 128)
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer client.Close() //nolint
	ready, _ := pollSockets(t, mod, pollSub{userData: 1, eventType: wasip1.EventTypeFdRead, fd: uint32(fd)})
	require.Equal(t, []uint64{1}, ready)
	requireErrnoResult(t, wasip1.ErrnoSuccess, mod, wasip1.SockAcceptName, uint64(fd), 0, 128)
	connFd, _ := mod.Memory().ReadUint32Le(128)
	got, ok = experimentalsock.Lookup(mod, int32(connFd))
	require.True(t, ok)
	_, isConn := got.(*net.TCPConn)
	require.True(t, isConn)

	// Closing the descriptor closes the listener.
	requireErrnoResult(t, wasip1.ErrnoSuccess, mod, wasip1.FdCloseName, uint64(fd))
	_, err = net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	require.Error(t, err)
}

// Blocking calls exit the module when their context is done, without
// RuntimeConfig.WithCloseOnContextDone.
func Test_blockingCallsStopOnContextDone(t *testing.T) {
	sub := func(eventType byte, fd uint32, timeout time.Duration) []byte {
		b := make([]byte, 48)
		b[8] = eventType
		if eventType == wasip1.EventTypeClock {
			binary.LittleEndian.PutUint64(b[24:], uint64(timeout))
		} else {
			binary.LittleEndian.PutUint32(b[16:], fd)
		}
		return b
	}
	listener := uint32(sys.FdPreopen)
	for _, tc := range []struct {
		name   string
		fn     string
		params []uint64
		subs   []byte
	}{
		{name: "sock_accept", fn: wasip1.SockAcceptName, params: []uint64{uint64(listener), 0, 128}},
		{name: "poll_oneoff socket", fn: wasip1.PollOneoffName, params: []uint64{0, 1024, 1, 2048},
			subs: sub(wasip1.EventTypeFdRead, listener, 0)},
		{name: "poll_oneoff sleep", fn: wasip1.PollOneoffName, params: []uint64{0, 1024, 1, 2048},
			subs: sub(wasip1.EventTypeClock, 0, time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := experimentalsock.WithConfig(testCtx, experimentalsock.NewConfig().WithTCPListener("127.0.0.1", 0))
			mod, r, _ := requireProxyModuleWithContext(ctx, t, wazero.NewModuleConfig().WithSysNanosleep())
			defer r.Close(testCtx)
			if tc.subs != nil {
				require.True(t, mod.Memory().Write(0, tc.subs))
			}
			ctx, cancel := context.WithCancel(testCtx)
			time.AfterFunc(100*time.Millisecond, cancel)
			start := time.Now()
			_, err := mod.ExportedFunction(tc.fn).Call(ctx, tc.params...)
			require.True(t, time.Since(start) < 5*time.Second, "returned after %v", time.Since(start))
			require.ErrorIs(t, err, context.Canceled)
		})
	}
}
