package wazevo

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/ChrisRx/wazero/api"
	"github.com/ChrisRx/wazero/experimental"
	"github.com/ChrisRx/wazero/internal/engine/wazevo/wazevoapi"
	"github.com/ChrisRx/wazero/internal/expctxkeys"
	"github.com/ChrisRx/wazero/internal/internalapi"
	"github.com/ChrisRx/wazero/internal/wasm"
	"github.com/ChrisRx/wazero/internal/wasmdebug"
	"github.com/ChrisRx/wazero/internal/wasmruntime"
)

type (
	// callEngine implements api.Function.
	callEngine struct {
		internalapi.WazeroOnly
		stack []byte
		// stackTop is the pointer to the *aligned* top of the stack. This must be updated
		// whenever the stack is changed. This is passed to the assembly function
		// at the very beginning of api.Function Call/CallWithStack.
		stackTop uintptr
		// executable is the pointer to the executable code for this function.
		executable         *byte
		preambleExecutable *byte
		// parent is the *moduleEngine from which this callEngine is created.
		parent *moduleEngine
		// indexInModule is the index of the function in the module.
		indexInModule wasm.Index
		// sizeOfParamResultSlice is the size of the parameter/result slice.
		sizeOfParamResultSlice int
		requiredParams         int
		// execCtx holds various information to be read/written by assembly functions.
		execCtx executionContext
		// execCtxPtr holds the pointer to the executionContext which doesn't change after callEngine is created.
		execCtxPtr        uintptr
		numberOfResults   int
		stackIteratorImpl stackIterator
		// tryRecords holds the try handler records the native try_table enter
		// stub writes (see wazevoapi.TryRecordSize): a sentinel, then one per
		// active handler, as many as execCtx.tryHandlerDepth.
		tryRecords []tryRecord
		// tryArena holds the chunks the locals save areas of try handlers are
		// taken from, in nesting order (see growTryHandlers).
		tryArena [][][2]uint64
		// tryTableResumeAddress is the address of the stub resuming a caught
		// try handler.
		tryTableResumeAddress *byte
		// pendingException holds the most recently caught exception, so handler
		// code can read its params after re-entry.
		pendingException *wasm.Exception
	}

	// executionContext is the struct to be read/written by assembly functions.
	executionContext struct {
		// exitCode holds the wazevoapi.ExitCode describing the state of the function execution.
		exitCode wazevoapi.ExitCode
		// callerModuleContextPtr holds the moduleContextOpaque for Go function calls.
		callerModuleContextPtr *byte
		// originalFramePointer holds the original frame pointer of the caller of the assembly function.
		originalFramePointer uintptr
		// originalStackPointer holds the original stack pointer of the caller of the assembly function.
		originalStackPointer uintptr
		// goReturnAddress holds the return address to go back to the caller of the assembly function.
		goReturnAddress uintptr
		// stackBottomPtr holds the pointer to the bottom of the stack.
		stackBottomPtr *byte
		// goCallReturnAddress holds the return address to go back to the caller of the Go function.
		goCallReturnAddress *byte
		// stackPointerBeforeGoCall holds the stack pointer before calling a Go function.
		stackPointerBeforeGoCall *uint64
		// stackGrowRequiredSize holds the required size of stack grow.
		stackGrowRequiredSize uintptr
		// memoryGrowTrampolineAddress holds the address of memory grow trampoline function.
		memoryGrowTrampolineAddress *byte
		// stackGrowCallTrampolineAddress holds the address of stack grow trampoline function.
		stackGrowCallTrampolineAddress *byte
		// checkModuleExitCodeTrampolineAddress holds the address of check-module-exit-code function.
		checkModuleExitCodeTrampolineAddress *byte
		// savedRegisters is the opaque spaces for save/restore registers.
		// We want to align 16 bytes for each register, so we use [64][2]uint64.
		savedRegisters [64][2]uint64
		// goFunctionCallCalleeModuleContextOpaque is the pointer to the target Go function's moduleContextOpaque.
		goFunctionCallCalleeModuleContextOpaque uintptr
		// tableGrowTrampolineAddress holds the address of table grow trampoline function.
		tableGrowTrampolineAddress *byte
		// refFuncTrampolineAddress holds the address of ref-func trampoline function.
		refFuncTrampolineAddress *byte
		// memmoveAddress holds the address of memmove function implemented by Go runtime. See memmove.go.
		memmoveAddress uintptr
		// framePointerBeforeGoCall holds the frame pointer before calling a Go function. Note: only used in amd64.
		framePointerBeforeGoCall uintptr
		// memoryWait32TrampolineAddress holds the address of memory_wait32 trampoline function.
		memoryWait32TrampolineAddress *byte
		// memoryWait32TrampolineAddress holds the address of memory_wait64 trampoline function.
		memoryWait64TrampolineAddress *byte
		// memoryNotifyTrampolineAddress holds the address of the memory_notify trampoline function.
		memoryNotifyTrampolineAddress *byte
		// throwAllocTrampolineAddress holds the address of the throw-alloc trampoline:
		// phase 1 of throw, which allocates the Exception heap object.
		throwAllocTrampolineAddress *byte
		// throwTrampolineAddress holds the address of the throw/throw_ref trampoline function.
		throwTrampolineAddress *byte
		// tryTableEnterTrampolineAddress holds the address of the try_table enter trampoline function.
		tryTableEnterTrampolineAddress *byte
		// tryTableLeaveTrampolineAddress holds the address of the try_table leave trampoline function.
		tryTableLeaveTrampolineAddress *byte
		// exceptionPtr holds the pointer to the Exception struct,
		// used on the throw side (throwAlloc stores the new Exception)
		// and on the catch side (catch_ref/catch_all_ref retrieve the exnref).
		exceptionPtr uintptr
		// exceptionParamsPtr points into exceptionPtr's Params slice
		// backing array. On the throw side, throwAlloc sets it so compiled
		// code can store params at [ptr + i*8]. On the catch side, compiled
		// handler blocks load params from the same pointer.
		exceptionParamsPtr uintptr
		// caughtExceptionClauseIdx is set by the dispatch loop to -1 on
		// TryTableEnter (normal path) or to the matched catch clause index
		// when an exception is caught. Compiled code loads this from execCtx
		// after the trampoline call to decide which handler to dispatch to.
		caughtExceptionClauseIdx int64
		// localsSaveAreaPtr points to the tryHandler's localsSaveArea slice
		// backing array. Handlers load locals from this slice.
		localsSaveAreaPtr uintptr
		// memclrAddress holds the address of memclrNoHeapPointers implemented
		// by the Go runtime. See memclr.go.
		memclrAddress uintptr
		// tryHandlerDepth is the number of active try_table handlers: entering
		// one (in the dispatch loop) sets it, and compiled code decrements it
		// when leaving one.
		tryHandlerDepth uint64
		// tryRecordsBase is the address of callEngine.tryRecords, and
		// tryRecordsCap the number of handlers there's room for.
		tryRecordsBase uintptr
		tryRecordsCap  uint64
		// tryTableGrowTrampolineAddress holds the address of the trampoline
		// the try_table enter stub calls to grow tryRecords or the arena.
		tryTableGrowTrampolineAddress *byte
		// tryResumeAddress is where the try_table resume stub jumps to.
		tryResumeAddress *byte
	}
)

func (c *callEngine) requiredInitialStackSize() int {
	const initialStackSizeDefault = 10240
	stackSize := initialStackSizeDefault
	paramResultInBytes := c.sizeOfParamResultSlice * 8 * 2 // * 8 because uint64 is 8 bytes, and *2 because we need both separated param/result slots.
	required := paramResultInBytes + 32 + 16               // 32 is enough to accommodate the call frame info, and 16 exists just in case when []byte is not aligned to 16 bytes.
	if required > stackSize {
		stackSize = required
	}
	return stackSize
}

func (c *callEngine) init() {
	stackSize := c.requiredInitialStackSize()
	if wazevoapi.StackGuardCheckEnabled {
		stackSize += wazevoapi.StackGuardCheckGuardPageSize
	}
	c.stack = make([]byte, stackSize)
	c.stackTop = alignedStackTop(c.stack)
	if wazevoapi.StackGuardCheckEnabled {
		c.execCtx.stackBottomPtr = &c.stack[wazevoapi.StackGuardCheckGuardPageSize]
	} else {
		c.execCtx.stackBottomPtr = &c.stack[0]
	}
	c.execCtxPtr = uintptr(unsafe.Pointer(&c.execCtx))
}

// alignedStackTop returns 16-bytes aligned stack top of given stack.
// 16 bytes should be good for all platform (arm64/amd64).
func alignedStackTop(s []byte) uintptr {
	stackAddr := uintptr(unsafe.Pointer(&s[len(s)-1]))
	return stackAddr - (stackAddr & (16 - 1))
}

// Definition implements api.Function.
func (c *callEngine) Definition() api.FunctionDefinition {
	return c.parent.module.Source.FunctionDefinition(c.indexInModule)
}

// Call implements api.Function.
func (c *callEngine) Call(ctx context.Context, params ...uint64) ([]uint64, error) {
	if c.requiredParams != len(params) {
		return nil, fmt.Errorf("expected %d params, but passed %d", c.requiredParams, len(params))
	}
	paramResultSlice := make([]uint64, c.sizeOfParamResultSlice)
	copy(paramResultSlice, params)
	if err := c.callWithStack(ctx, paramResultSlice); err != nil {
		return nil, err
	}
	return paramResultSlice[:c.numberOfResults], nil
}

func (c *callEngine) addFrame(builder wasmdebug.ErrorBuilder, addr uintptr) (def api.FunctionDefinition, listener experimental.FunctionListener) {
	eng := c.parent.parent.parent
	cm := eng.compiledModuleOfAddr(addr)
	if cm == nil {
		// This case, the module might have been closed and deleted from the engine.
		// We fall back to searching the imported modules that can be referenced from this callEngine.

		// First, we check itself.
		if checkAddrInBytes(addr, c.parent.parent.executable) {
			cm = c.parent.parent
		} else {
			// Otherwise, search all imported modules. TODO: maybe recursive, but not sure it's useful in practice.
			p := c.parent
			for i := range p.importedFunctions {
				candidate := p.importedFunctions[i].me.parent
				if checkAddrInBytes(addr, candidate.executable) {
					cm = candidate
					break
				}
			}
		}
	}

	if cm != nil {
		index := cm.functionIndexOf(addr)
		def = cm.module.FunctionDefinition(cm.module.ImportFunctionCount + index)
		var sources []string
		if dw := cm.module.DWARFLines; dw != nil {
			sourceOffset := cm.getSourceOffset(addr)
			sources = dw.Line(sourceOffset)
		}
		builder.AddFrame(def.DebugName(), def.ParamTypes(), def.ResultTypes(), sources)
		if len(cm.listeners) > 0 {
			listener = cm.listeners[index]
		}
	}
	return
}

// CallWithStack implements api.Function.
func (c *callEngine) CallWithStack(ctx context.Context, paramResultStack []uint64) (err error) {
	if c.sizeOfParamResultSlice > len(paramResultStack) {
		return fmt.Errorf("need %d params, but stack size is %d", c.sizeOfParamResultSlice, len(paramResultStack))
	}
	return c.callWithStack(ctx, paramResultStack)
}

// CallWithStack implements api.Function.
func (c *callEngine) callWithStack(ctx context.Context, paramResultStack []uint64) (err error) {
	snapshotEnabled := ctx.Value(expctxkeys.EnableSnapshotterKey{}) != nil
	if snapshotEnabled {
		ctx = context.WithValue(ctx, expctxkeys.SnapshotterKey{}, c)
	}

	if wazevoapi.StackGuardCheckEnabled {
		defer func() {
			wazevoapi.CheckStackGuardPage(c.stack)
		}()
	}

	p := c.parent
	ensureTermination := p.parent.ensureTermination
	m := p.module
	if ensureTermination {
		select {
		case <-ctx.Done():
			// If the provided context is already done, close the module and return the error.
			m.CloseWithCtxErr(ctx)
			return m.FailIfClosed()
		default:
		}
	}

	// Clear any stale try_table handlers from a previous call.
	c.resetTryHandlers()

	var paramResultPtr *uint64
	if len(paramResultStack) > 0 {
		paramResultPtr = &paramResultStack[0]
	}
	defer func() {
		r := recover()
		if s, ok := r.(*snapshot); ok {
			// A snapshot that wasn't handled was created by a different call engine possibly from a nested wasm invocation,
			// let it propagate up to be handled by the caller.
			panic(s)
		}
		if r != nil {
			type listenerForAbort struct {
				def api.FunctionDefinition
				lsn experimental.FunctionListener
			}

			var listeners []listenerForAbort
			builder := wasmdebug.NewErrorBuilder()
			if c.execCtx.stackPointerBeforeGoCall != nil {
				def, lsn := c.addFrame(builder, uintptr(unsafe.Pointer(c.execCtx.goCallReturnAddress)))
				if lsn != nil {
					listeners = append(listeners, listenerForAbort{def, lsn})
				}
				returnAddrs := unwindStack(
					uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)),
					c.execCtx.framePointerBeforeGoCall,
					c.stackTop,
					nil,
				)
				if len(returnAddrs) > 1 {
					for _, retAddr := range returnAddrs[:len(returnAddrs)-1] { // the last return addr is the trampoline, so we skip it.
						def, lsn = c.addFrame(builder, retAddr)
						if lsn != nil {
							listeners = append(listeners, listenerForAbort{def, lsn})
						}
					}
				}
			}
			err = builder.FromRecovered(r)

			for _, lsn := range listeners {
				lsn.lsn.Abort(ctx, m, lsn.def, err)
			}
		} else {
			if err != wasmruntime.ErrRuntimeStackOverflow { // Stackoverflow case shouldn't be panic (to avoid extreme stack unwinding).
				err = c.parent.module.FailIfClosed()
			}
		}

		if err != nil {
			// Ensures that we can reuse this callEngine even after an error.
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			c.resetTryHandlers()
		}
	}()

	if ensureTermination {
		done := m.CloseModuleOnCanceledOrTimeout(ctx)
		defer done()
	}

	if c.stackTop&(16-1) != 0 {
		panic("BUG: stack must be aligned to 16 bytes")
	}
	entrypoint(c.preambleExecutable, c.executable, c.execCtxPtr, c.parent.opaquePtr, paramResultPtr, c.stackTop)
	for {
		switch ec := c.execCtx.exitCode; ec & wazevoapi.ExitCodeMask {
		case wazevoapi.ExitCodeOK:
			return nil
		case wazevoapi.ExitCodeGrowStack:
			oldsp := uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall))
			oldTop := c.stackTop
			oldStack := c.stack
			var newsp, newfp uintptr
			if wazevoapi.StackGuardCheckEnabled {
				newsp, newfp, err = c.growStackWithGuarded()
			} else {
				newsp, newfp, err = c.growStack()
			}
			if err != nil {
				return err
			}
			adjustClonedStack(oldsp, oldTop, newsp, newfp, c.stackTop)
			c.rebaseTryHandlers(oldTop, c.stackTop)
			// Old stack must be alive until the new stack is adjusted.
			runtime.KeepAlive(oldStack)
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr, newsp, newfp)
		case wazevoapi.ExitCodeGrowMemory:
			mod := c.callerModuleInstance()
			mem := mod.MemoryInstance
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			argRes := &s[0]
			if res, ok := mem.Grow(uint32(*argRes)); !ok {
				*argRes = uint64(0xffffffff) // = -1 in signed 32-bit integer.
			} else {
				*argRes = uint64(res)
			}
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr, uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeTableGrow:
			mod := c.callerModuleInstance()
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			tableIndex, num, ref := uint32(s[0]), uint32(s[1]), uintptr(s[2])
			table := mod.Tables[tableIndex]
			s[0] = uint64(uint32(int32(table.Grow(num, ref))))
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCallGoFunction:
			index := wazevoapi.GoFunctionIndexFromExitCode(ec)
			f := hostModuleGoFuncFromOpaque[api.GoFunction](index, c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			func() {
				if snapshotEnabled {
					defer snapshotRecoverFn(c)
				}
				f.Call(ctx, goCallStackView(c.execCtx.stackPointerBeforeGoCall))
			}()
			// Back to the native code.
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCallGoFunctionWithListener:
			index := wazevoapi.GoFunctionIndexFromExitCode(ec)
			f := hostModuleGoFuncFromOpaque[api.GoFunction](index, c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			listeners := hostModuleListenersSliceFromOpaque(c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			// Call Listener.Before.
			callerModule := c.callerModuleInstance()
			listener := listeners[index]
			hostModule := hostModuleFromOpaque(c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			def := hostModule.FunctionDefinition(wasm.Index(index))
			listener.Before(ctx, callerModule, def, s, c.stackIterator(true))
			// Call into the Go function.
			func() {
				if snapshotEnabled {
					defer snapshotRecoverFn(c)
				}
				f.Call(ctx, s)
			}()
			// Call Listener.After.
			listener.After(ctx, callerModule, def, s)
			// Back to the native code.
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCallGoModuleFunction:
			index := wazevoapi.GoFunctionIndexFromExitCode(ec)
			f := hostModuleGoFuncFromOpaque[api.GoModuleFunction](index, c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			mod := c.callerModuleInstance()
			func() {
				if snapshotEnabled {
					defer snapshotRecoverFn(c)
				}
				f.Call(ctx, mod, goCallStackView(c.execCtx.stackPointerBeforeGoCall))
			}()
			// Back to the native code.
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCallGoModuleFunctionWithListener:
			index := wazevoapi.GoFunctionIndexFromExitCode(ec)
			f := hostModuleGoFuncFromOpaque[api.GoModuleFunction](index, c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			listeners := hostModuleListenersSliceFromOpaque(c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			// Call Listener.Before.
			callerModule := c.callerModuleInstance()
			listener := listeners[index]
			hostModule := hostModuleFromOpaque(c.execCtx.goFunctionCallCalleeModuleContextOpaque)
			def := hostModule.FunctionDefinition(wasm.Index(index))
			listener.Before(ctx, callerModule, def, s, c.stackIterator(true))
			// Call into the Go function.
			func() {
				if snapshotEnabled {
					defer snapshotRecoverFn(c)
				}
				f.Call(ctx, callerModule, s)
			}()
			// Call Listener.After.
			listener.After(ctx, callerModule, def, s)
			// Back to the native code.
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCallListenerBefore:
			stack := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			index := wasm.Index(stack[0])
			mod := c.callerModuleInstance()
			listener := mod.Engine.(*moduleEngine).listeners[index]
			def := mod.Source.FunctionDefinition(index + mod.Source.ImportFunctionCount)
			listener.Before(ctx, mod, def, stack[1:], c.stackIterator(false))
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCallListenerAfter:
			stack := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			index := wasm.Index(stack[0])
			mod := c.callerModuleInstance()
			listener := mod.Engine.(*moduleEngine).listeners[index]
			def := mod.Source.FunctionDefinition(index + mod.Source.ImportFunctionCount)
			listener.After(ctx, mod, def, stack[1:])
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeCheckModuleExitCode:
			// Note: this operation must be done in Go, not native code. The reason is that
			// native code cannot be preempted and that means it can block forever if there are not
			// enough OS threads (which we don't have control over).
			if err := m.FailIfClosed(); err != nil {
				panic(err)
			}
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeRefFunc:
			mod := c.callerModuleInstance()
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			funcIndex := wasm.Index(s[0])
			ref := mod.Engine.FunctionInstanceReference(funcIndex)
			s[0] = uint64(ref)
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeMemoryWait32:
			mod := c.callerModuleInstance()
			mem := mod.MemoryInstance
			if !mem.Shared {
				panic(wasmruntime.ErrRuntimeExpectedSharedMemory)
			}

			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			timeout, exp, addr := int64(s[0]), uint32(s[1]), uintptr(s[2])
			base := uintptr(unsafe.Pointer(&mem.Buffer[0]))

			offset := uint32(addr - base)
			res := mem.Wait32(offset, exp, timeout, func(mem *wasm.MemoryInstance, offset uint32) uint32 {
				addr := unsafe.Add(unsafe.Pointer(&mem.Buffer[0]), offset)
				return atomic.LoadUint32((*uint32)(addr))
			})
			s[0] = res
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeMemoryWait64:
			mod := c.callerModuleInstance()
			mem := mod.MemoryInstance
			if !mem.Shared {
				panic(wasmruntime.ErrRuntimeExpectedSharedMemory)
			}

			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			timeout, exp, addr := int64(s[0]), uint64(s[1]), uintptr(s[2])
			base := uintptr(unsafe.Pointer(&mem.Buffer[0]))

			offset := uint32(addr - base)
			res := mem.Wait64(offset, exp, timeout, func(mem *wasm.MemoryInstance, offset uint32) uint64 {
				addr := unsafe.Add(unsafe.Pointer(&mem.Buffer[0]), offset)
				return atomic.LoadUint64((*uint64)(addr))
			})
			s[0] = uint64(res)
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeMemoryNotify:
			mod := c.callerModuleInstance()
			mem := mod.MemoryInstance

			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			count, addr := uint32(s[0]), s[1]
			offset := uint32(uintptr(addr) - uintptr(unsafe.Pointer(&mem.Buffer[0])))
			res := mem.Notify(offset, count)
			s[0] = uint64(res)
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeUnreachable:
			panic(wasmruntime.ErrRuntimeUnreachable)
		case wazevoapi.ExitCodeMemoryOutOfBounds:
			panic(wasmruntime.ErrRuntimeOutOfBoundsMemoryAccess)
		case wazevoapi.ExitCodeTableOutOfBounds:
			panic(wasmruntime.ErrRuntimeInvalidTableAccess)
		case wazevoapi.ExitCodeIndirectCallNullPointer:
			panic(wasmruntime.ErrRuntimeInvalidTableAccess)
		case wazevoapi.ExitCodeIndirectCallTypeMismatch:
			panic(wasmruntime.ErrRuntimeIndirectCallTypeMismatch)
		case wazevoapi.ExitCodeIntegerOverflow:
			panic(wasmruntime.ErrRuntimeIntegerOverflow)
		case wazevoapi.ExitCodeIntegerDivisionByZero:
			panic(wasmruntime.ErrRuntimeIntegerDivideByZero)
		case wazevoapi.ExitCodeInvalidConversionToInteger:
			panic(wasmruntime.ErrRuntimeInvalidConversionToInteger)
		case wazevoapi.ExitCodeUnalignedAtomic:
			panic(wasmruntime.ErrRuntimeUnalignedAtomic)
		case wazevoapi.ExitCodeThrowAlloc:
			// Allocate the Exception heap object sized exactly to the tag's
			// param count. Sets exceptionParamsPtr so compiled code can
			// store params, and returns the exnref via the stack slot.
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			tagIndex := int(s[0])
			mod := c.callerModuleInstance()
			tag := mod.Tags[tagIndex]
			nParams := len(tag.Type.Params)
			exn := &wasm.Exception{Tag: tag, Params: make([]uint64, nParams)}
			c.pendingException = exn // GC root: keeps exn alive while compiled code writes params
			if nParams > 0 {
				c.execCtx.exceptionParamsPtr = uintptr(unsafe.Pointer(&exn.Params[0]))
			}
			// Return the exnref to compiled code via the stack slot.
			s[0] = uint64(uintptr(unsafe.Pointer(exn)))
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeThrow:
			// Throw trampoline: (execCtx, exnref) → ().
			// Reads the exnref from the stack, searches for a matching handler.
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			// Read the Exception pointer directly from the uint64 value to avoid
			// conversion from uintptr into unsafe.Pointer, which triggers checkptr.
			exn := *(**wasm.Exception)(unsafe.Pointer(&s[0]))
			if !c.doHandleException(exn) {
				panic(wasmruntime.ErrRuntimeUncaughtException)
			}
			if len(exn.Params) > 0 {
				c.execCtx.exceptionParamsPtr = uintptr(unsafe.Pointer(&exn.Params[0]))
			}
			c.execCtx.exceptionPtr = uintptr(unsafe.Pointer(exn))
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeNullReference:
			panic(wasmruntime.ErrRuntimeNullReference)
		case wazevoapi.ExitCodeTryTableEnter:
			// The native enter stub is out of handler records or locals
			// space: make room, and it tries again.
			s := goCallStackView(c.execCtx.stackPointerBeforeGoCall)
			c.growTryHandlers(s[0] >> 32)
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		case wazevoapi.ExitCodeTryTableLeave:
			// Compiled code leaves try_tables itself (decrementing
			// tryHandlerDepth), but pop here too for code that calls the
			// trampoline.
			if d := c.execCtx.tryHandlerDepth; d > 0 {
				c.execCtx.tryHandlerDepth = d - 1
				c.execCtx.localsSaveAreaPtr = uintptr(c.tryRecord(int(d) - 2)[wazevoapi.TryRecordLocals/8])
			}
			c.execCtx.exitCode = wazevoapi.ExitCodeOK
			afterGoFunctionCallEntrypoint(c.execCtx.goCallReturnAddress, c.execCtxPtr,
				uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall)
		default:
			panic("BUG")
		}
	}
}

// doHandleException tries to match the given exception against the active
// try handlers, innermost first. On a match, it pops the handlers at and
// above it and sets up the execution context to resume it (by the resume
// stub, at the return address of its enter call) with the matched clause
// index. Returns true if handled.
func (c *callEngine) doHandleException(exn *wasm.Exception) bool {
	for i := int(c.execCtx.tryHandlerDepth) - 1; i >= 0; i-- {
		r := c.tryRecord(i)
		tryTableID := wazevoapi.TryTableIDFromExitCode(wazevoapi.ExitCode(r[wazevoapi.TryRecordCode/8]))
		// The tag index in catch clauses is relative to the module that
		// entered the try_table, not the one that threw.
		mod := moduleInstanceFromOpaquePtr(*(**byte)(unsafe.Pointer(&r[wazevoapi.TryRecordModuleCtx/8])))
		info := &mod.Engine.(*moduleEngine).parent.tryTableInfo[tryTableID]
		for clauseIdx, clause := range info.CatchClauses {
			matched := false
			switch clause.Kind {
			case wasm.CatchKindCatch, wasm.CatchKindCatchRef:
				matched = mod.Tags[clause.TagIndex] == exn.Tag
			case wasm.CatchKindCatchAll, wasm.CatchKindCatchAllRef:
				matched = true
			}
			if !matched {
				continue
			}
			ec := &c.execCtx
			ec.localsSaveAreaPtr = uintptr(r[wazevoapi.TryRecordLocals/8])
			regs := r[wazevoapi.TryRecordRegisters/8:]
			for j := range ec.savedRegisters[:len(regs)/2] {
				ec.savedRegisters[j] = [2]uint64{regs[2*j], regs[2*j+1]}
			}
			// The stack as the enter call's caller had it, after the call.
			sp := uintptr(r[wazevoapi.TryRecordSP/8]) + tryTableEnterReturnAddressSize
			ec.stackPointerBeforeGoCall = *(**uint64)(unsafe.Pointer(&sp))
			ec.framePointerBeforeGoCall = uintptr(r[wazevoapi.TryRecordFP/8])
			ec.goCallReturnAddress = c.tryTableResumeAddress
			ec.tryResumeAddress = *(**byte)(unsafe.Pointer(&r[wazevoapi.TryRecordReturn/8]))
			ec.tryHandlerDepth = uint64(i)
			// Store the caught exception so handler code can read params.
			c.pendingException = exn
			ec.caughtExceptionClauseIdx = int64(clauseIdx)
			return true
		}
	}
	return false
}

// tryRecord is a try handler record (see wazevoapi.TryRecordSize).
type tryRecord [wazevoapi.TryRecordSize / 8]uint64

// tryRecord returns the record of the i-th active handler, the sentinel for -1.
func (c *callEngine) tryRecord(i int) *tryRecord {
	return &c.tryRecords[i+1]
}

// tryArenaChunkSize is the minimum size of a chunk of the locals arena.
const tryArenaChunkSize = 64 << 10

// resetTryHandlers drops all try handlers, and points the sentinel record
// at the start of the arena.
func (c *callEngine) resetTryHandlers() {
	c.execCtx.tryHandlerDepth = 0
	c.execCtx.localsSaveAreaPtr = 0
	if len(c.tryRecords) == 0 {
		return
	}
	s := c.tryRecord(-1)
	*s = tryRecord{}
	if len(c.tryArena) == 0 {
		s[wazevoapi.TryRecordArenaChunk/8] = ^uint64(0) // -1: none yet
		return
	}
	c.setTryArena(s, 0)
}

// setTryArena makes the record r's arena (where the next record's locals
// save area goes) chunk i of the arena.
func (c *callEngine) setTryArena(r *tryRecord, i int) {
	chunk := c.tryArena[i]
	start := uintptr(unsafe.Pointer(&chunk[0]))
	r[wazevoapi.TryRecordArenaEnd/8] = uint64(start)
	r[wazevoapi.TryRecordArenaLimit/8] = uint64(start + uintptr(len(chunk))*16)
	r[wazevoapi.TryRecordArenaChunk/8] = uint64(i)
}

// growTryHandlers makes room for the record of the next try handler, and a
// locals save area of localsSize bytes for it.
//
// Save areas are taken from the arena in nesting order, each record keeping
// where the next one's goes, so leaving a try_table frees its area without
// doing anything. An area can't move, compiled code holds pointers to it,
// so when a chunk is full, the next handlers take theirs from a new one,
// the chunk after it. Chunks after the one the innermost handler's next area
// would come from are free.
func (c *callEngine) growTryHandlers(localsSize uint64) {
	depth := int(c.execCtx.tryHandlerDepth)
	if n := len(c.tryRecords) - 1; depth >= n {
		records := make([]tryRecord, max(16, 2*n, depth+1)+1)
		copy(records, c.tryRecords)
		fresh := len(c.tryRecords) == 0
		c.tryRecords = records
		c.execCtx.tryRecordsBase = uintptr(unsafe.Pointer(&records[0]))
		c.execCtx.tryRecordsCap = uint64(len(records) - 1)
		if fresh {
			c.resetTryHandlers()
		}
	}
	prev := c.tryRecord(depth - 1)
	if prev[wazevoapi.TryRecordArenaEnd/8]+localsSize <= prev[wazevoapi.TryRecordArenaLimit/8] {
		return
	}
	i := int(int64(prev[wazevoapi.TryRecordArenaChunk/8])) + 1
	size := max(tryArenaChunkSize, int(localsSize)) / 16
	if i == len(c.tryArena) {
		c.tryArena = append(c.tryArena, nil)
	}
	if len(c.tryArena[i]) < size {
		c.tryArena[i] = make([][2]uint64, size)
	}
	c.setTryArena(prev, i)
}

// rebaseTryHandlers adjusts the stack and frame pointers in the records of
// the active try handlers after the stack moved from oldTop to top.
func (c *callEngine) rebaseTryHandlers(oldTop, top uintptr) {
	for i := range int(c.execCtx.tryHandlerDepth) {
		r := c.tryRecord(i)
		r[wazevoapi.TryRecordSP/8] = uint64(uintptr(r[wazevoapi.TryRecordSP/8]) - oldTop + top)
		r[wazevoapi.TryRecordFP/8] = uint64(uintptr(r[wazevoapi.TryRecordFP/8]) - oldTop + top)
	}
}

func (c *callEngine) callerModuleInstance() *wasm.ModuleInstance {
	return moduleInstanceFromOpaquePtr(c.execCtx.callerModuleContextPtr)
}

const callStackCeiling = uintptr(50000000) // in uint64 (8 bytes) == 400000000 bytes in total == 400mb.

func (c *callEngine) growStackWithGuarded() (newSP uintptr, newFP uintptr, err error) {
	if wazevoapi.StackGuardCheckEnabled {
		wazevoapi.CheckStackGuardPage(c.stack)
	}
	newSP, newFP, err = c.growStack()
	if err != nil {
		return
	}
	if wazevoapi.StackGuardCheckEnabled {
		c.execCtx.stackBottomPtr = &c.stack[wazevoapi.StackGuardCheckGuardPageSize]
	}
	return
}

// growStack grows the stack, and returns the new stack pointer.
func (c *callEngine) growStack() (newSP, newFP uintptr, err error) {
	currentLen := uintptr(len(c.stack))
	if callStackCeiling < currentLen {
		err = wasmruntime.ErrRuntimeStackOverflow
		return
	}

	newLen := 2*currentLen + c.execCtx.stackGrowRequiredSize + 16 // Stack might be aligned to 16 bytes, so add 16 bytes just in case.
	newSP, newFP, c.stackTop, c.stack = c.cloneStack(newLen)
	c.execCtx.stackBottomPtr = &c.stack[0]
	return
}

func (c *callEngine) cloneStack(l uintptr) (newSP, newFP, newTop uintptr, newStack []byte) {
	newStack = make([]byte, l)

	relSp := c.stackTop - uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall))
	relFp := c.stackTop - c.execCtx.framePointerBeforeGoCall

	// Copy the existing contents in the previous Go-allocated stack into the new one.
	var prevStackAligned, newStackAligned []byte
	{
		//nolint:staticcheck
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&prevStackAligned))
		sh.Data = c.stackTop - relSp
		sh.Len = int(relSp)
		sh.Cap = int(relSp)
	}
	newTop = alignedStackTop(newStack)
	{
		newSP = newTop - relSp
		newFP = newTop - relFp
		//nolint:staticcheck
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&newStackAligned))
		sh.Data = newSP
		sh.Len = int(relSp)
		sh.Cap = int(relSp)
	}
	copy(newStackAligned, prevStackAligned)
	return
}

func (c *callEngine) stackIterator(onHostCall bool) experimental.StackIterator {
	c.stackIteratorImpl.reset(c, onHostCall)
	return &c.stackIteratorImpl
}

// stackIterator implements experimental.StackIterator.
type stackIterator struct {
	retAddrs      []uintptr
	retAddrCursor int
	eng           *engine
	pc            uint64

	currentDef *wasm.FunctionDefinition
}

func (si *stackIterator) reset(c *callEngine, onHostCall bool) {
	if onHostCall {
		si.retAddrs = append(si.retAddrs[:0], uintptr(unsafe.Pointer(c.execCtx.goCallReturnAddress)))
	} else {
		si.retAddrs = si.retAddrs[:0]
	}
	si.retAddrs = unwindStack(uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall)), c.execCtx.framePointerBeforeGoCall, c.stackTop, si.retAddrs)
	si.retAddrs = si.retAddrs[:len(si.retAddrs)-1] // the last return addr is the trampoline, so we skip it.
	si.retAddrCursor = 0
	si.eng = c.parent.parent.parent
}

// Next implements the same method as documented on experimental.StackIterator.
func (si *stackIterator) Next() bool {
	if si.retAddrCursor >= len(si.retAddrs) {
		return false
	}

	addr := si.retAddrs[si.retAddrCursor]
	cm := si.eng.compiledModuleOfAddr(addr)
	if cm != nil {
		index := cm.functionIndexOf(addr)
		def := cm.module.FunctionDefinition(cm.module.ImportFunctionCount + index)
		si.currentDef = def
		si.retAddrCursor++
		si.pc = uint64(addr)
		return true
	}
	return false
}

// ProgramCounter implements the same method as documented on experimental.StackIterator.
func (si *stackIterator) ProgramCounter() experimental.ProgramCounter {
	return experimental.ProgramCounter(si.pc)
}

// Function implements the same method as documented on experimental.StackIterator.
func (si *stackIterator) Function() experimental.InternalFunction {
	return si
}

// Definition implements the same method as documented on experimental.InternalFunction.
func (si *stackIterator) Definition() api.FunctionDefinition {
	return si.currentDef
}

// SourceOffsetForPC implements the same method as documented on experimental.InternalFunction.
func (si *stackIterator) SourceOffsetForPC(pc experimental.ProgramCounter) uint64 {
	upc := uintptr(pc)
	cm := si.eng.compiledModuleOfAddr(upc)
	return cm.getSourceOffset(upc)
}

// snapshot implements experimental.Snapshot
type snapshot struct {
	sp, fp, top    uintptr
	returnAddress  *byte
	stack          []byte
	savedRegisters [64][2]uint64
	ret            []uint64
	c              *callEngine
}

// Snapshot implements the same method as documented on experimental.Snapshotter.
func (c *callEngine) Snapshot() experimental.Snapshot {
	returnAddress := c.execCtx.goCallReturnAddress
	oldTop, oldSp := c.stackTop, uintptr(unsafe.Pointer(c.execCtx.stackPointerBeforeGoCall))
	newSP, newFP, newTop, newStack := c.cloneStack(uintptr(len(c.stack)) + 16)
	adjustClonedStack(oldSp, oldTop, newSP, newFP, newTop)
	return &snapshot{
		sp:             newSP,
		fp:             newFP,
		top:            newTop,
		savedRegisters: c.execCtx.savedRegisters,
		returnAddress:  returnAddress,
		stack:          newStack,
		c:              c,
	}
}

// Restore implements the same method as documented on experimental.Snapshot.
func (s *snapshot) Restore(ret []uint64) {
	s.ret = ret
	panic(s)
}

func (s *snapshot) doRestore() {
	spp := *(**uint64)(unsafe.Pointer(&s.sp))
	view := goCallStackView(spp)
	copy(view, s.ret)

	c := s.c
	c.stack = s.stack
	c.stackTop = s.top
	ec := &c.execCtx
	ec.stackBottomPtr = &c.stack[0]
	ec.stackPointerBeforeGoCall = spp
	ec.framePointerBeforeGoCall = s.fp
	ec.goCallReturnAddress = s.returnAddress
	ec.savedRegisters = s.savedRegisters
}

// Error implements the same method on error.
func (s *snapshot) Error() string {
	return "unhandled snapshot restore, this generally indicates restore was called from a different " +
		"exported function invocation than snapshot"
}

func snapshotRecoverFn(c *callEngine) {
	if r := recover(); r != nil {
		if s, ok := r.(*snapshot); ok && s.c == c {
			s.doRestore()
		} else {
			panic(r)
		}
	}
}
