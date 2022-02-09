use super::{CompactUnwindInfoUnwinderError, CompactUnwindInfoUnwinding, CuiUnwindResult};
use crate::arch::ArchX86_64;
use crate::rules::UnwindRuleX86_64;
use crate::unwind_result::UnwindResult;
use crate::unwinders::FramepointerUnwinderX86_64;
use crate::unwindregs::UnwindRegsX86_64;
use macho_unwind_info::opcodes::{OpcodeX86_64, RegisterNameX86_64};

impl CompactUnwindInfoUnwinding for ArchX86_64 {
    fn unwind_first<F>(
        opcode: u32,
        regs: &mut UnwindRegsX86_64,
        _pc: u64,
        _rel_pc: u32,
        read_mem: &mut F,
    ) -> CuiUnwindResult<UnwindRuleX86_64>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let opcode = OpcodeX86_64::parse(opcode);
        match opcode {
            OpcodeX86_64::Null => CuiUnwindResult::ExecRule(UnwindRuleX86_64::JustReturn),
            OpcodeX86_64::FramelessImmediate {
                stack_size_in_bytes,
                saved_regs,
            } => {
                if stack_size_in_bytes == 8 {
                    CuiUnwindResult::ExecRule(UnwindRuleX86_64::JustReturn)
                } else {
                    let bp_positon_from_outside = saved_regs
                        .iter()
                        .rev()
                        .flatten()
                        .position(|r| *r == RegisterNameX86_64::Rbp);
                    let bp_offset_from_sp = bp_positon_from_outside
                        .map(|pos| stack_size_in_bytes as i32 - 2 * 8 - pos as i32 * 8);
                    match bp_offset_from_sp.map(|offset| i8::try_from(offset / 8)) {
                        None => CuiUnwindResult::ExecRule(UnwindRuleX86_64::OffsetSp {
                            sp_offset_by_8: stack_size_in_bytes / 8,
                        }),
                        Some(Ok(bp_storage_offset_from_sp_by_8)) => {
                            CuiUnwindResult::ExecRule(UnwindRuleX86_64::OffsetSpAndRestoreBp {
                                sp_offset_by_8: stack_size_in_bytes / 8,
                                bp_storage_offset_from_sp_by_8,
                            })
                        }
                        Some(Err(_)) => {
                            eprintln!("Uncacheable rule in compact unwind info unwinder because Frameless stack size doesn't fit");
                            let sp = regs.sp();
                            let new_sp = sp + stack_size_in_bytes as u64;
                            let return_address =
                                match read_mem(new_sp - 8) {
                                    Ok(ra) => ra,
                                    Err(_) => return CuiUnwindResult::Err(
                                        CompactUnwindInfoUnwinderError::CouldNotReadReturnAddress,
                                    ),
                                };
                            if let Some(bp_offset_from_sp) = bp_offset_from_sp {
                                let new_bp = match read_mem(
                                    sp.wrapping_add(bp_offset_from_sp as i64 as u64),
                                ) {
                                    Ok(bp) => bp,
                                    Err(_) => {
                                        return CuiUnwindResult::Err(
                                            CompactUnwindInfoUnwinderError::CouldNotReadBp,
                                        )
                                    }
                                };
                                regs.set_bp(new_bp);
                            }
                            regs.set_sp(new_sp);
                            CuiUnwindResult::Uncacheable(return_address)
                        }
                    }
                }
            }
            OpcodeX86_64::FramelessIndirect { .. } => {
                CuiUnwindResult::Err(CompactUnwindInfoUnwinderError::CantHandleFramelessIndirect)
            }
            OpcodeX86_64::Dwarf { eh_frame_fde } => CuiUnwindResult::NeedDwarf(eh_frame_fde),
            OpcodeX86_64::FrameBased { .. } => {
                // TODO: Detect if we're in an epilogue, by seeing if the current instruction restores
                // registers from the stack (and then keep reading) or is a return instruction.
                match FramepointerUnwinderX86_64.unwind_first() {
                    Ok(UnwindResult::ExecRule(rule)) => CuiUnwindResult::ExecRule(rule),
                    Ok(UnwindResult::Uncacheable(return_address)) => {
                        CuiUnwindResult::Uncacheable(return_address)
                    }
                    Err(err) => CuiUnwindResult::Err(err.into()),
                }
            }
            OpcodeX86_64::UnrecognizedKind(kind) => {
                CuiUnwindResult::Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
            }
            OpcodeX86_64::InvalidFramelessImmediate => {
                CuiUnwindResult::Err(CompactUnwindInfoUnwinderError::InvalidFramelessImmediate)
            }
        }
    }

    fn unwind_next<F>(
        opcode: u32,
        regs: &mut UnwindRegsX86_64,
        read_mem: &mut F,
    ) -> CuiUnwindResult<UnwindRuleX86_64>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let opcode = OpcodeX86_64::parse(opcode);
        match opcode {
            OpcodeX86_64::Null => {
                CuiUnwindResult::Err(CompactUnwindInfoUnwinderError::FunctionHasNoInfo)
            }
            OpcodeX86_64::FramelessImmediate {
                stack_size_in_bytes,
                saved_regs,
            } => {
                if stack_size_in_bytes == 8 {
                    CuiUnwindResult::ExecRule(UnwindRuleX86_64::JustReturn)
                } else {
                    let bp_positon_from_outside = saved_regs
                        .iter()
                        .rev()
                        .flatten()
                        .position(|r| *r == RegisterNameX86_64::Rbp);
                    let bp_offset_from_sp = bp_positon_from_outside
                        .map(|pos| stack_size_in_bytes as i32 - 2 * 8 - pos as i32 * 8);
                    match bp_offset_from_sp.map(|offset| i8::try_from(offset / 8)) {
                        None => CuiUnwindResult::ExecRule(UnwindRuleX86_64::OffsetSp {
                            sp_offset_by_8: stack_size_in_bytes / 8,
                        }),
                        Some(Ok(bp_storage_offset_from_sp_by_8)) => {
                            CuiUnwindResult::ExecRule(UnwindRuleX86_64::OffsetSpAndRestoreBp {
                                sp_offset_by_8: stack_size_in_bytes / 8,
                                bp_storage_offset_from_sp_by_8,
                            })
                        }
                        Some(Err(_)) => {
                            eprintln!("Uncacheable rule in compact unwind info unwinder because Frameless stack size doesn't fit");
                            let sp = regs.sp();
                            let new_sp = sp + stack_size_in_bytes as u64;
                            let return_address =
                                match read_mem(new_sp - 8) {
                                    Ok(ra) => ra,
                                    Err(_) => return CuiUnwindResult::Err(
                                        CompactUnwindInfoUnwinderError::CouldNotReadReturnAddress,
                                    ),
                                };
                            if let Some(bp_offset_from_sp) = bp_offset_from_sp {
                                let new_bp = match read_mem(
                                    sp.wrapping_add(bp_offset_from_sp as i64 as u64),
                                ) {
                                    Ok(bp) => bp,
                                    Err(_) => {
                                        return CuiUnwindResult::Err(
                                            CompactUnwindInfoUnwinderError::CouldNotReadBp,
                                        )
                                    }
                                };
                                regs.set_bp(new_bp);
                            }
                            regs.set_sp(new_sp);
                            CuiUnwindResult::Uncacheable(return_address)
                        }
                    }
                }
            }
            OpcodeX86_64::InvalidFramelessImmediate => {
                CuiUnwindResult::Err(CompactUnwindInfoUnwinderError::InvalidFramelessImmediate)
            }
            OpcodeX86_64::FramelessIndirect { .. } => {
                CuiUnwindResult::Err(CompactUnwindInfoUnwinderError::CantHandleFramelessIndirect)
            }
            OpcodeX86_64::Dwarf { eh_frame_fde } => CuiUnwindResult::NeedDwarf(eh_frame_fde),
            OpcodeX86_64::FrameBased { .. } => {
                CuiUnwindResult::ExecRule(UnwindRuleX86_64::UseFramePointer)
            }
            OpcodeX86_64::UnrecognizedKind(kind) => {
                CuiUnwindResult::Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
            }
        }
    }
}
