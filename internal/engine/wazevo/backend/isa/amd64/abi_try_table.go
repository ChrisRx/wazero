package amd64

import (
	"github.com/ChrisRx/wazero/internal/engine/wazevo/backend/regalloc"
	"github.com/ChrisRx/wazero/internal/engine/wazevo/wazevoapi"
)

// CompileTryTableEnter implements backend.Machine.
//
// Called with the execution context in rax and the enter code in rbx, the
// return address at [rsp]. It only uses caller-saved registers.
//
//	retry:
//		mov r11, [rax+depth]
//		cmp r11, [rax+cap]
//		jae slow                       ; out of records
//		shl r11, log2(recordSize)
//		add r11, [rax+base]            ; r11 = previous record
//		mov r10, rbx
//		shr r10, 32                    ; r10 = locals size
//		mov rcx, [r11+arenaEnd]
//		mov rdi, [r11+arenaLimit]
//		lea rsi, [rcx+r10]
//		cmp rsi, rdi
//		ja slow                        ; out of arena
//		mov r9, [r11+locals]           ; inherited save area
//		test r10, r10
//		jz 1f
//		mov r9, rcx                    ; or a new one
//		mov [rax+localsSaveAreaPtr], rcx
//	1:	mov r8, [r11+arenaChunk]
//		add r11, recordSize            ; r11 = this record
//		mov [r11+locals], r9
//		mov [r11+arenaEnd], rsi
//		mov [r11+arenaLimit], rdi
//		mov [r11+arenaChunk], r8
//		mov [r11+sp], rsp
//		mov [r11+fp], rbp
//		mov rcx, [rsp]
//		mov [r11+return], rcx
//		mov [r11+code], rbx
//		mov rcx, [rax+callerModuleContextPtr]
//		mov [r11+moduleCtx], rcx
//		(save the callee-saved registers at [r11+registers])
//		mov r11, [rax+depth]
//		add r11, 1
//		mov [rax+depth], r11
//		mov qword [rax+caughtClauseIdx], -1
//		ret
//	slow:
//		push rax
//		push rbx
//		call [rax+growTrampoline]
//		pop rbx
//		pop rax
//		jmp retry
func (m *machine) CompileTryTableEnter() []byte {
	cur := m.allocateNop()
	m.rootInstr = cur
	execCtx, code := raxVReg, rbxVReg
	ctxMem := func(off wazevoapi.Offset) operand {
		return newOperandMem(m.newAmodeImmReg(off.U32(), execCtx))
	}
	recMem := func(off int) operand {
		return newOperandMem(m.newAmodeImmReg(uint32(off), r11VReg))
	}
	link := func(i *instruction) { cur = linkInstr(cur, i) }

	retryNop, retry := m.allocateBrTarget()
	link(retryNop)
	link(m.allocateInstr().asMov64MR(ctxMem(wazevoapi.ExecutionContextOffsetTryHandlerDepth), r11VReg))
	link(m.allocateInstr().asCmpRmiR(true, ctxMem(wazevoapi.ExecutionContextOffsetTryRecordsCap), r11VReg, true))
	jaeSlow := m.allocateInstr()
	link(jaeSlow)
	link(m.allocateInstr().asShiftR(shiftROpShiftLeft, newOperandImm32(wazevoapi.TryRecordSizeLog2), r11VReg, true))
	link(m.allocateInstr().asAluRmiR(aluRmiROpcodeAdd, ctxMem(wazevoapi.ExecutionContextOffsetTryRecordsBase), r11VReg, true))
	link(m.allocateInstr().asMovRR(code, r10VReg, true))
	link(m.allocateInstr().asShiftR(shiftROpShiftRightLogical, newOperandImm32(32), r10VReg, true))
	link(m.allocateInstr().asMov64MR(recMem(wazevoapi.TryRecordArenaEnd), rcxVReg))
	link(m.allocateInstr().asMov64MR(recMem(wazevoapi.TryRecordArenaLimit), rdiVReg))
	link(m.allocateInstr().asMovRR(rcxVReg, rsiVReg, true))
	link(m.allocateInstr().asAluRmiR(aluRmiROpcodeAdd, newOperandReg(r10VReg), rsiVReg, true))
	link(m.allocateInstr().asCmpRmiR(true, newOperandReg(rdiVReg), rsiVReg, true))
	jaSlow := m.allocateInstr()
	link(jaSlow)
	link(m.allocateInstr().asMov64MR(recMem(wazevoapi.TryRecordLocals), r9VReg))
	link(m.allocateInstr().asCmpRmiR(false, newOperandReg(r10VReg), r10VReg, true))
	jzInherit := m.allocateInstr()
	link(jzInherit)
	link(m.allocateInstr().asMovRR(rcxVReg, r9VReg, true))
	link(m.allocateInstr().asMovRM(rcxVReg, ctxMem(wazevoapi.ExecutionContextOffsetLocalsSaveAreaPtr), 8))
	inheritNop, inherit := m.allocateBrTarget()
	link(inheritNop)
	jzInherit.asJmpIf(condZ, newOperandLabel(inherit))
	link(m.allocateInstr().asMov64MR(recMem(wazevoapi.TryRecordArenaChunk), r8VReg))
	link(m.allocateInstr().asAluRmiR(aluRmiROpcodeAdd, newOperandImm32(wazevoapi.TryRecordSize), r11VReg, true))
	link(m.allocateInstr().asMovRM(r9VReg, recMem(wazevoapi.TryRecordLocals), 8))
	link(m.allocateInstr().asMovRM(rsiVReg, recMem(wazevoapi.TryRecordArenaEnd), 8))
	link(m.allocateInstr().asMovRM(rdiVReg, recMem(wazevoapi.TryRecordArenaLimit), 8))
	link(m.allocateInstr().asMovRM(r8VReg, recMem(wazevoapi.TryRecordArenaChunk), 8))
	link(m.allocateInstr().asMovRM(rspVReg, recMem(wazevoapi.TryRecordSP), 8))
	link(m.allocateInstr().asMovRM(rbpVReg, recMem(wazevoapi.TryRecordFP), 8))
	link(m.allocateInstr().asMov64MR(newOperandMem(m.newAmodeImmReg(0, rspVReg)), rcxVReg))
	link(m.allocateInstr().asMovRM(rcxVReg, recMem(wazevoapi.TryRecordReturn), 8))
	link(m.allocateInstr().asMovRM(code, recMem(wazevoapi.TryRecordCode), 8))
	link(m.allocateInstr().asMov64MR(ctxMem(wazevoapi.ExecutionContextOffsetCallerModuleContextPtr), rcxVReg))
	link(m.allocateInstr().asMovRM(rcxVReg, recMem(wazevoapi.TryRecordModuleCtx), 8))
	cur = m.saveRegisters(cur, r11VReg, wazevoapi.TryRecordRegisters, calleeSavedVRegs)
	link(m.allocateInstr().asMov64MR(ctxMem(wazevoapi.ExecutionContextOffsetTryHandlerDepth), r11VReg))
	link(m.allocateInstr().asAluRmiR(aluRmiROpcodeAdd, newOperandImm32(1), r11VReg, true))
	link(m.allocateInstr().asMovRM(r11VReg, ctxMem(wazevoapi.ExecutionContextOffsetTryHandlerDepth), 8))
	link(m.allocateInstr().asImm(rcxVReg, ^uint64(0), true))
	link(m.allocateInstr().asMovRM(rcxVReg, ctxMem(wazevoapi.ExecutionContextOffsetCaughtExceptionClauseIdx), 8))
	link(m.allocateInstr().asRet())

	slowNop, slow := m.allocateBrTarget()
	link(slowNop)
	jaeSlow.asJmpIf(condNB, newOperandLabel(slow))
	jaSlow.asJmpIf(condNBE, newOperandLabel(slow))
	link(m.allocateInstr().asPush64(newOperandReg(execCtx)))
	link(m.allocateInstr().asPush64(newOperandReg(code)))
	link(m.allocateInstr().asCallIndirect(ctxMem(wazevoapi.ExecutionContextOffsetTryTableGrowTrampolineAddress), nil))
	link(m.allocateInstr().asPop64(code))
	link(m.allocateInstr().asPop64(execCtx))
	link(m.allocateInstr().asJmp(newOperandLabel(retry)))

	m.encodeWithoutSSA(m.rootInstr)
	return m.c.Buf()
}

// CompileTryTableResume implements backend.Machine.
//
// Entered from Go (afterGoFunctionCallEntrypoint) with the execution context
// in rax, and rsp and rbp as the enter call's caller had them.
func (m *machine) CompileTryTableResume() []byte {
	cur := m.allocateNop()
	m.rootInstr = cur
	cur = m.restoreRegistersInExecutionContext(cur, raxVReg, calleeSavedVRegs)
	linkInstr(cur, m.allocateInstr().asJmp(newOperandMem(
		m.newAmodeImmReg(wazevoapi.ExecutionContextOffsetTryResumeAddress.U32(), raxVReg))))
	m.encodeWithoutSSA(m.rootInstr)
	return m.c.Buf()
}

// saveRegisters stores regs at [base+offset], 16 bytes apart.
func (m *machine) saveRegisters(cur *instruction, base regalloc.VReg, offset int, regs []regalloc.VReg) *instruction {
	for _, v := range regs {
		mem := newOperandMem(m.newAmodeImmReg(uint32(offset), base))
		store := m.allocateInstr()
		switch v.RegType() {
		case regalloc.RegTypeInt:
			store.asMovRM(v, mem, 8)
		case regalloc.RegTypeFloat:
			store.asXmmMovRM(sseOpcodeMovdqu, v, mem)
		default:
			panic("BUG")
		}
		cur = linkInstr(cur, store)
		offset += 16
	}
	return cur
}
