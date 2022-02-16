use super::arch::ArchAarch64;
use super::framepointer::FramepointerUnwinderAarch64;
use super::unwind_rule::UnwindRuleAarch64;
use super::unwindregs::UnwindRegsAarch64;
use crate::macho::{CompactUnwindInfoUnwinderError, CompactUnwindInfoUnwinding, CuiUnwindResult};
use crate::unwind_result::UnwindResult;
use macho_unwind_info::opcodes::OpcodeArm64;

impl CompactUnwindInfoUnwinding for ArchAarch64 {
    fn unwind_first<F>(
        opcode: u32,
        _regs: &mut UnwindRegsAarch64,
        _pc: u64,
        _rel_pc: u32,
        _read_mem: &mut F,
    ) -> CuiUnwindResult<UnwindRuleAarch64>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let opcode = OpcodeArm64::parse(opcode);
        match opcode {
            OpcodeArm64::Null => CuiUnwindResult::ExecRule(UnwindRuleAarch64::NoOp),
            OpcodeArm64::Frameless {
                stack_size_in_bytes,
            } => {
                if stack_size_in_bytes == 0 {
                    CuiUnwindResult::ExecRule(UnwindRuleAarch64::NoOp)
                } else {
                    CuiUnwindResult::ExecRule(UnwindRuleAarch64::OffsetSp {
                        sp_offset_by_16: stack_size_in_bytes / 16,
                    })
                }
            }
            OpcodeArm64::Dwarf { eh_frame_fde } => CuiUnwindResult::NeedDwarf(eh_frame_fde),
            OpcodeArm64::FrameBased { .. } => {
                // Each pair takes one 4-byte instruction to save or restore. fp gets updated after saving or before restoring.
                // Use this to do something smart for prologues / epilogues.
                // let prologue_end = function.start_address +
                //         saved_reg_pair_count as u32 * 4 + // 4 bytes per pair
                //         4 + // save fp and lr
                //         4; // set fp to the new value
                // if rel_pc < prologue_end {
                //     // TODO: Disassemble instructions from the beginning to see how deep we are into the stack.
                //     FramepointerUnwinderAarch64.unwind_next(regs, read_mem)?

                // TODO: Detect if we're in an epilogue, by seeing if the current instruction restores
                // registers from the stack (and then keep reading) or is a return instruction.
                match FramepointerUnwinderAarch64.unwind_first() {
                    UnwindResult::ExecRule(rule) => CuiUnwindResult::ExecRule(rule),
                    UnwindResult::Uncacheable(return_address) => {
                        CuiUnwindResult::Uncacheable(return_address)
                    }
                }
            }
            OpcodeArm64::UnrecognizedKind(kind) => {
                CuiUnwindResult::Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
            }
        }
    }

    fn unwind_next<F>(
        opcode: u32,
        _regs: &mut UnwindRegsAarch64,
        _read_mem: &mut F,
    ) -> CuiUnwindResult<UnwindRuleAarch64>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let opcode = OpcodeArm64::parse(opcode);
        match opcode {
            OpcodeArm64::Null => {
                CuiUnwindResult::Err(CompactUnwindInfoUnwinderError::FunctionHasNoInfo)
            }
            OpcodeArm64::Frameless { .. } => {
                CuiUnwindResult::Err(CompactUnwindInfoUnwinderError::CallerCannotBeFrameless)
            }
            OpcodeArm64::Dwarf { eh_frame_fde } => CuiUnwindResult::NeedDwarf(eh_frame_fde),
            OpcodeArm64::FrameBased { .. } => {
                CuiUnwindResult::ExecRule(UnwindRuleAarch64::UseFramePointer)
            }
            OpcodeArm64::UnrecognizedKind(kind) => {
                CuiUnwindResult::Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
            }
        }
    }
}
