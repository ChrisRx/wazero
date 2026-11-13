//go:build unix && (amd64 || arm64)

package platform

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// ReservedMemorySupported reports whether ReserveMemory is available.
const ReservedMemorySupported = true

// ReservedMemorySize covers every address a 32-bit linear memory access can
// compute: a 32-bit address plus a 32-bit static offset plus the widest
// access (16 bytes), rounded up to a wasm page.
const ReservedMemorySize = 8<<30 + 64<<10

// ReserveMemory maps ReservedMemorySize bytes of zeroed, readable and
// writable memory that is only backed by physical pages once touched.
func ReserveMemory() ([]byte, error) {
	return unix.Mmap(-1, 0, ReservedMemorySize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANON|unix.MAP_PRIVATE|unix.MAP_NORESERVE)
}

// ZeroReservedMemory zeroes b, a page-aligned part of a ReserveMemory
// mapping. On Linux the pages are dropped instead, so untouched ones stay
// unbacked.
func ZeroReservedMemory(b []byte) {
	if len(b) == 0 {
		return
	}
	if runtime.GOOS == "linux" && unix.Madvise(b, unix.MADV_DONTNEED) == nil {
		return
	}
	clear(b)
}

// ReleaseReservedMemory drops the physical pages of a ReserveMemory mapping
// while keeping it mapped, so later accesses don't fault. Linux only; a
// no-op elsewhere, where FreeReservedMemory releases them.
func ReleaseReservedMemory(b []byte) {
	if runtime.GOOS == "linux" {
		_ = unix.Madvise(b, unix.MADV_DONTNEED)
	}
}

// FreeReservedMemory unmaps a ReserveMemory mapping.
func FreeReservedMemory(b []byte) error {
	return unix.Munmap(b[:cap(b)])
}
