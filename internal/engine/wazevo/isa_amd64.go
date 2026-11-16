//go:build amd64

package wazevo

import (
	"unsafe"

	"github.com/ChrisRx/wazero/internal/engine/wazevo/backend"
	"github.com/ChrisRx/wazero/internal/engine/wazevo/backend/isa/amd64"
)

func newMachine() backend.Machine {
	return amd64.NewBackend()
}

// unwindStack is a function to unwind the stack, and appends return addresses to `returnAddresses` slice.
// The implementation must be aligned with the ABI/Calling convention.
func unwindStack(sp, fp, top uintptr, returnAddresses []uintptr) []uintptr {
	return amd64.UnwindStack(sp, fp, top, returnAddresses)
}

// goCallStackView is a function to get a view of the stack before a Go call, which
// is the view of the stack allocated in CompileGoFunctionTrampoline.
func goCallStackView(stackPointerBeforeGoCall *uint64) []uint64 {
	return amd64.GoCallStackView(stackPointerBeforeGoCall)
}

// adjustClonedStack is a function to adjust the stack after it is grown.
// More precisely, absolute addresses (frame pointers) in the stack must be adjusted.
func adjustClonedStack(oldsp, oldTop, sp, fp, top uintptr) {
	amd64.AdjustClonedStack(oldsp, oldTop, sp, fp, top)
}

// rebaseRestoredWindow fixes the frame pointers saved in a try_table's copy of
// the top of the stack (tryHandler.window), written back at sp after the stack
// moved from oldTop to top: the saved RBPs, starting at fp, that are inside it
// still point into the old stack. Saved RBPs beyond it are in live frames,
// which growing the stack already rebased.
func rebaseRestoredWindow(sp, size, fp, oldTop, top uintptr) {
	for cur := fp; cur >= sp && cur+8 <= sp+size; {
		p := *(**uintptr)(unsafe.Pointer(&cur))
		*p = *p - oldTop + top
		cur = *p
	}
}
