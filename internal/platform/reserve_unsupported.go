//go:build !((linux || darwin) && (amd64 || arm64))

package platform

import "errors"

// ReservedMemorySupported reports whether ReserveMemory is available.
const ReservedMemorySupported = false

// ReservedMemorySize is the size of a ReserveMemory mapping.
const ReservedMemorySize = 8<<30 + 64<<10

// ReserveMemory is not supported on this platform.
func ReserveMemory() ([]byte, error) {
	return nil, errors.New("reserved memory is not supported on this platform")
}

// ZeroReservedMemory is not supported on this platform.
func ZeroReservedMemory([]byte) {}

// ReleaseReservedMemory is not supported on this platform.
func ReleaseReservedMemory([]byte) {}

// FreeReservedMemory is not supported on this platform.
func FreeReservedMemory([]byte) error { return nil }
