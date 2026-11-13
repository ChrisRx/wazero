package wasm

import (
	"fmt"
	"runtime"

	"github.com/ChrisRx/wazero/experimental"
	"github.com/ChrisRx/wazero/internal/platform"
)

// reservedMemory backs the memory of a module compiled with UncheckedMemory:
// one platform.ReserveMemory mapping that covers every address the module
// can compute, so compiled code needs no bounds checks and the buffer never
// moves. Accesses past the current length land in the reservation instead
// of trapping. Growing zeroes the newly exposed range first, since such
// accesses may have written there.
type reservedMemory struct {
	buf []byte
	// mapping is the whole reservation, for releasing it.
	mapping []byte
}

var _ experimental.LinearMemory = (*reservedMemory)(nil)

func newReservedMemory() *reservedMemory {
	buf, err := platform.ReserveMemory()
	if err != nil {
		panic(fmt.Errorf("reserving linear memory: %w", err))
	}
	return &reservedMemory{buf: buf[:0], mapping: buf}
}

// unmapWhenUnreachable unmaps the reservation once mem, whose memory it
// backs, can no longer be reached. Not on Free: a module can be closed from
// another goroutine while its code or a host function it called still runs
// and accesses the memory, which only stops referencing mem once it
// returns.
func (r *reservedMemory) unmapWhenUnreachable(mem *MemoryInstance) {
	runtime.AddCleanup(mem, func(mapping []byte) {
		_ = platform.FreeReservedMemory(mapping)
	}, r.mapping)
}

// Reallocate implements experimental.LinearMemory.
func (r *reservedMemory) Reallocate(size uint64) []byte {
	if size > uint64(cap(r.buf)) {
		return nil
	}
	if old := uint64(len(r.buf)); size > old {
		platform.ZeroReservedMemory(r.buf[old:size])
	}
	r.buf = r.buf[:size]
	return r.buf[:size:size]
}

// Free implements experimental.LinearMemory. It releases the physical pages
// but keeps the mapping valid, see unmapWhenUnreachable.
func (r *reservedMemory) Free() {
	platform.ReleaseReservedMemory(r.mapping)
}
