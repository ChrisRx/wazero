package arm64

import (
	"github.com/ChrisRx/wazero/internal/engine/wazevo/backend/regalloc"
	"github.com/ChrisRx/wazero/internal/engine/wazevo/wazevoapi"
)

// CompileTryTableEnter implements backend.Machine.
//
// Called with the execution context in x0, the enter code in x1 and the
// return address in lr. It only uses caller-saved registers.
//
//	retry:
//		ldr x9, [x0, #depth]
//		ldr x10, [x0, #cap]
//		subs xzr, x9, x10
//		b.hs slow                      ; out of records
//		ldr x10, [x0, #base]
//		add x11, x10, x9, lsl #log2(recordSize)  ; x11 = previous record
//		lsr x13, x1, #32               ; x13 = locals size
//		ldr x14, [x11, #arenaEnd]
//		ldr x15, [x11, #arenaLimit]
//		add x16, x14, x13
//		subs xzr, x16, x15
//		b.hi slow                      ; out of arena
//		ldr x17, [x11, #locals]        ; inherited save area
//		cbz x13, 1f
//		mov x17, x14                   ; or a new one
//		str x14, [x0, #localsSaveAreaPtr]
//	1:	add x12, x11, #recordSize      ; x12 = this record
//		ldr x10, [x11, #arenaChunk]
//		str x17, [x12, #locals]
//		str x16, [x12, #arenaEnd]
//		str x15, [x12, #arenaLimit]
//		str x10, [x12, #arenaChunk]
//		mov x17, sp
//		str x17, [x12, #sp]
//		str x29, [x12, #fp]
//		str lr, [x12, #return]
//		str x1, [x12, #code]
//		ldr x17, [x0, #callerModuleContextPtr]
//		str x17, [x12, #moduleCtx]
//		(save the callee-saved registers at [x12, #registers])
//		add x9, x9, #1
//		str x9, [x0, #depth]
//		movn x17, #0
//		str x17, [x0, #caughtClauseIdx]
//		ret
//	slow:
//		stp x0, x1, [sp, #-16]!
//		stp lr, lr, [sp, #-16]!
//		ldr x27, [x0, #growTrampoline]
//		blr x27
//		ldp lr, x17, [sp], #16
//		ldp x0, x1, [sp], #16
//		b retry
func (m *machine) CompileTryTableEnter() []byte {
	cur := m.allocateInstr().asNop0()
	m.rootInstr = cur
	link := func(i *instruction) *instruction {
		cur = linkInstr(cur, i)
		return i
	}
	mem := func(base regalloc.VReg, off int64) *addressMode {
		mode := m.amodePool.Allocate()
		*mode = addressMode{kind: addressModeKindRegUnsignedImm12, rn: base, imm: off}
		return mode
	}
	ld := func(dst, base regalloc.VReg, off int64) {
		i := m.allocateInstr()
		i.asULoad(dst, mem(base, off), 64)
		link(i)
	}
	st := func(src, base regalloc.VReg, off int64) {
		i := m.allocateInstr()
		i.asStore(operandNR(src), mem(base, off), 64)
		link(i)
	}
	alu := func(op aluOp, rd regalloc.VReg, rn, rm operand) {
		i := m.allocateInstr()
		i.asALU(op, rd, rn, rm, true)
		link(i)
	}
	condBr := func(c cond) *instruction {
		i := m.allocateInstr()
		i.asCondBr(c, labelInvalid, true)
		return link(i)
	}

	retry := link(m.allocateInstr().asNop0())
	ld(x9VReg, x0VReg, wazevoapi.ExecutionContextOffsetTryHandlerDepth.I64())
	ld(x10VReg, x0VReg, wazevoapi.ExecutionContextOffsetTryRecordsCap.I64())
	alu(aluOpSubS, xzrVReg, operandNR(x9VReg), operandNR(x10VReg))
	outOfRecords := condBr(hs.asCond())
	ld(x10VReg, x0VReg, wazevoapi.ExecutionContextOffsetTryRecordsBase.I64())
	alu(aluOpAdd, x11VReg, operandNR(x10VReg), operandSR(x9VReg, wazevoapi.TryRecordSizeLog2, shiftOpLSL))
	lsr := m.allocateInstr()
	lsr.asALUShift(aluOpLsr, x13VReg, operandNR(x1VReg), operandShiftImm(32), true)
	link(lsr)
	ld(x14VReg, x11VReg, wazevoapi.TryRecordArenaEnd)
	ld(x15VReg, x11VReg, wazevoapi.TryRecordArenaLimit)
	alu(aluOpAdd, x16VReg, operandNR(x14VReg), operandNR(x13VReg))
	alu(aluOpSubS, xzrVReg, operandNR(x16VReg), operandNR(x15VReg))
	outOfArena := condBr(hi.asCond())
	ld(x17VReg, x11VReg, wazevoapi.TryRecordLocals)
	inherit := condBr(registerAsRegZeroCond(x13VReg))
	link(m.allocateInstr().asMove64(x17VReg, x14VReg))
	st(x14VReg, x0VReg, wazevoapi.ExecutionContextOffsetLocalsSaveAreaPtr.I64())
	inherited := link(m.allocateInstr().asNop0())
	alu(aluOpAdd, x12VReg, operandNR(x11VReg), operandImm12(wazevoapi.TryRecordSize, 0))
	ld(x10VReg, x11VReg, wazevoapi.TryRecordArenaChunk)
	st(x17VReg, x12VReg, wazevoapi.TryRecordLocals)
	st(x16VReg, x12VReg, wazevoapi.TryRecordArenaEnd)
	st(x15VReg, x12VReg, wazevoapi.TryRecordArenaLimit)
	st(x10VReg, x12VReg, wazevoapi.TryRecordArenaChunk)
	link(m.allocateInstr().asMove64(x17VReg, spVReg))
	st(x17VReg, x12VReg, wazevoapi.TryRecordSP)
	st(x29VReg, x12VReg, wazevoapi.TryRecordFP)
	st(lrVReg, x12VReg, wazevoapi.TryRecordReturn)
	st(x1VReg, x12VReg, wazevoapi.TryRecordCode)
	ld(x17VReg, x0VReg, wazevoapi.ExecutionContextOffsetCallerModuleContextPtr.I64())
	st(x17VReg, x12VReg, wazevoapi.TryRecordModuleCtx)
	offset := int64(wazevoapi.TryRecordRegisters)
	for _, v := range calleeSavedRegistersSorted {
		i := m.allocateInstr()
		size := byte(64)
		if v.RegType() == regalloc.RegTypeFloat {
			size = 128
		}
		i.asStore(operandNR(v), mem(x12VReg, offset), size)
		link(i)
		offset += 16
	}
	alu(aluOpAdd, x9VReg, operandNR(x9VReg), operandImm12(1, 0))
	st(x9VReg, x0VReg, wazevoapi.ExecutionContextOffsetTryHandlerDepth.I64())
	movn := m.allocateInstr()
	movn.asMOVN(x17VReg, 0, 0, true)
	link(movn)
	st(x17VReg, x0VReg, wazevoapi.ExecutionContextOffsetCaughtExceptionClauseIdx.I64())
	ret := m.allocateInstr()
	ret.asRet()
	link(ret)

	slow := link(m.allocateInstr().asNop0())
	pair := func(load bool, a, b regalloc.VReg) {
		i := m.allocateInstr()
		if load {
			i.asLoadPair64(a, b, addressModePreOrPostIndex(m, spVReg, 16, false))
		} else {
			i.asStorePair64(a, b, addressModePreOrPostIndex(m, spVReg, -16, true))
		}
		link(i)
	}
	pair(false, x0VReg, x1VReg)
	pair(false, lrVReg, lrVReg)
	ld(tmpRegVReg, x0VReg, wazevoapi.ExecutionContextOffsetTryTableGrowTrampolineAddress.I64())
	call := m.allocateInstr()
	call.asCallIndirect(tmpRegVReg, nil)
	link(call)
	pair(true, lrVReg, x17VReg)
	pair(true, x0VReg, x1VReg)
	again := m.allocateInstr()
	again.asBr(labelInvalid)
	link(again)

	outOfRecords.condBrOffsetResolve(codeDistance(outOfRecords, slow))
	outOfArena.condBrOffsetResolve(codeDistance(outOfArena, slow))
	inherit.condBrOffsetResolve(codeDistance(inherit, inherited))
	again.brOffsetResolve(-codeDistance(retry, again))

	m.encode(m.rootInstr)
	return m.compiler.Buf()
}

// CompileTryTableResume implements backend.Machine.
//
// Entered from Go (afterGoFunctionCallEntrypoint) with the execution context
// in x0 and sp as the enter call's caller had it.
func (m *machine) CompileTryTableResume() []byte {
	cur := m.allocateInstr().asNop0()
	m.rootInstr = cur
	cur = m.restoreRegistersInExecutionContext(cur, calleeSavedRegistersSorted)
	ldr := m.allocateInstr()
	mode := m.amodePool.Allocate()
	*mode = addressMode{
		kind: addressModeKindRegUnsignedImm12,
		rn:   x0VReg, imm: wazevoapi.ExecutionContextOffsetTryResumeAddress.I64(),
	}
	ldr.asULoad(tmpRegVReg, mode, 64)
	cur = linkInstr(cur, ldr)
	br := m.allocateInstr()
	br.asTailCallIndirect(tmpRegVReg, nil)
	linkInstr(cur, br)
	m.encode(m.rootInstr)
	return m.compiler.Buf()
}

// codeDistance is the size of the code from from (included) to to
// (excluded), which must follow it.
func codeDistance(from, to *instruction) int64 {
	var n int64
	for cur := from; cur != to; cur = cur.next {
		n += cur.size()
	}
	return n
}
