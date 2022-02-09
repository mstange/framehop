use gimli::Reader;

use super::super::{DwarfUnwinder, FramepointerUnwinderX86_64};
use super::{CompactUnwindInfoUnwinderError, CompactUnwindInfoUnwinding};
use crate::arch::ArchX86_64;
use crate::rules::UnwindRuleX86_64;
use crate::unwind_result::UnwindResult;
use crate::unwindregs::UnwindRegsX86_64;
use macho_unwind_info::opcodes::{OpcodeX86_64, RegisterNameX86_64};

impl CompactUnwindInfoUnwinding for ArchX86_64 {
    fn unwind_first<F, R>(
        opcode: u32,
        regs: &mut UnwindRegsX86_64,
        pc: u64,
        _rel_pc: u32,
        dwarf_unwinder: Option<&mut DwarfUnwinder<R, ArchX86_64>>,
        read_mem: &mut F,
    ) -> Result<UnwindResult<UnwindRuleX86_64>, CompactUnwindInfoUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader,
    {
        let opcode = OpcodeX86_64::parse(opcode);
        let unwind_result = match opcode {
            OpcodeX86_64::Null => UnwindResult::ExecRule(UnwindRuleX86_64::JustReturn),
            OpcodeX86_64::FramelessImmediate {
                stack_size_in_bytes,
                saved_regs,
            } => {
                if stack_size_in_bytes == 8 {
                    UnwindResult::ExecRule(UnwindRuleX86_64::JustReturn)
                } else {
                    let bp_positon_from_outside = saved_regs
                        .iter()
                        .rev()
                        .flatten()
                        .position(|r| *r == RegisterNameX86_64::Rbp);
                    let bp_offset_from_sp = bp_positon_from_outside
                        .map(|pos| stack_size_in_bytes as i32 - 2 * 8 - pos as i32 * 8);
                    match bp_offset_from_sp.map(|offset| i8::try_from(offset / 8)) {
                        None => UnwindResult::ExecRule(UnwindRuleX86_64::OffsetSp {
                            sp_offset_by_8: stack_size_in_bytes / 8,
                        }),
                        Some(Ok(bp_storage_offset_from_sp_by_8)) => {
                            UnwindResult::ExecRule(UnwindRuleX86_64::OffsetSpAndRestoreBp {
                                sp_offset_by_8: stack_size_in_bytes / 8,
                                bp_storage_offset_from_sp_by_8,
                            })
                        }
                        Some(Err(_)) => {
                            eprintln!("Uncacheable rule in compact unwind info unwinder because Frameless stack size doesn't fit");
                            let sp = regs.sp();
                            let new_sp = sp + stack_size_in_bytes as u64;
                            let return_address = read_mem(new_sp - 8).map_err(|_| {
                                CompactUnwindInfoUnwinderError::CouldNotReadReturnAddress
                            })?;
                            if let Some(bp_offset_from_sp) = bp_offset_from_sp {
                                let bp = read_mem(sp.wrapping_add(bp_offset_from_sp as i64 as u64))
                                    .map_err(|_| CompactUnwindInfoUnwinderError::CouldNotReadBp)?;
                                regs.set_bp(bp);
                            }
                            regs.set_sp(new_sp);
                            UnwindResult::Uncacheable(return_address)
                        }
                    }
                }
            }
            OpcodeX86_64::FramelessIndirect { .. } => {
                return Err(CompactUnwindInfoUnwinderError::CantHandleFramelessIndirect);
            }
            OpcodeX86_64::Dwarf { eh_frame_fde } => {
                let dwarf_unwinder =
                    dwarf_unwinder.ok_or(CompactUnwindInfoUnwinderError::NoDwarfUnwinder)?;
                dwarf_unwinder.unwind_first_with_fde(regs, pc, eh_frame_fde, read_mem)?
            }
            OpcodeX86_64::FrameBased { .. } => {
                // TODO: Detect if we're in an epilogue, by seeing if the current instruction restores
                // registers from the stack (and then keep reading) or is a return instruction.
                FramepointerUnwinderX86_64.unwind_first()?
            }
            OpcodeX86_64::UnrecognizedKind(kind) => {
                return Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
            }
            OpcodeX86_64::InvalidFramelessImmediate => {
                return Err(CompactUnwindInfoUnwinderError::InvalidFramelessImmediate)
            }
        };

        Ok(unwind_result)
    }

    fn unwind_next<F, R>(
        opcode: u32,
        regs: &mut UnwindRegsX86_64,
        return_address: u64,
        dwarf_unwinder: Option<&mut DwarfUnwinder<R, ArchX86_64>>,
        read_mem: &mut F,
    ) -> Result<UnwindResult<UnwindRuleX86_64>, CompactUnwindInfoUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader,
    {
        let opcode = OpcodeX86_64::parse(opcode);
        let unwind_result = match opcode {
            OpcodeX86_64::Null => {
                return Err(CompactUnwindInfoUnwinderError::FunctionHasNoInfo);
            }
            OpcodeX86_64::FramelessImmediate {
                stack_size_in_bytes,
                saved_regs,
            } => {
                if stack_size_in_bytes == 8 {
                    UnwindResult::ExecRule(UnwindRuleX86_64::JustReturn)
                } else {
                    let bp_positon_from_outside = saved_regs
                        .iter()
                        .rev()
                        .flatten()
                        .position(|r| *r == RegisterNameX86_64::Rbp);
                    let bp_offset_from_sp = bp_positon_from_outside
                        .map(|pos| stack_size_in_bytes as i32 - 2 * 8 - pos as i32 * 8);
                    match bp_offset_from_sp.map(|offset| i8::try_from(offset / 8)) {
                        None => UnwindResult::ExecRule(UnwindRuleX86_64::OffsetSp {
                            sp_offset_by_8: stack_size_in_bytes / 8,
                        }),
                        Some(Ok(bp_storage_offset_from_sp_by_8)) => {
                            UnwindResult::ExecRule(UnwindRuleX86_64::OffsetSpAndRestoreBp {
                                sp_offset_by_8: stack_size_in_bytes / 8,
                                bp_storage_offset_from_sp_by_8,
                            })
                        }
                        Some(Err(_)) => {
                            eprintln!("Uncacheable rule in compact unwind info unwinder because Frameless stack size doesn't fit");
                            let sp = regs.sp();
                            let new_sp = sp + stack_size_in_bytes as u64;
                            let return_address = read_mem(new_sp - 8).map_err(|_| {
                                CompactUnwindInfoUnwinderError::CouldNotReadReturnAddress
                            })?;
                            if let Some(bp_offset_from_sp) = bp_offset_from_sp {
                                let bp = read_mem(sp.wrapping_add(bp_offset_from_sp as i64 as u64))
                                    .map_err(|_| CompactUnwindInfoUnwinderError::CouldNotReadBp)?;
                                regs.set_bp(bp);
                            }
                            regs.set_sp(new_sp);
                            UnwindResult::Uncacheable(return_address)
                        }
                    }
                }
            }
            OpcodeX86_64::InvalidFramelessImmediate => {
                return Err(CompactUnwindInfoUnwinderError::InvalidFramelessImmediate);
            }
            OpcodeX86_64::FramelessIndirect { .. } => {
                return Err(CompactUnwindInfoUnwinderError::CantHandleFramelessIndirect);
            }
            OpcodeX86_64::Dwarf { eh_frame_fde } => {
                let dwarf_unwinder =
                    dwarf_unwinder.ok_or(CompactUnwindInfoUnwinderError::NoDwarfUnwinder)?;
                dwarf_unwinder.unwind_next_with_fde(regs, return_address, eh_frame_fde, read_mem)?
            }
            OpcodeX86_64::FrameBased { .. } => {
                UnwindResult::ExecRule(UnwindRuleX86_64::UseFramePointer)
            }
            OpcodeX86_64::UnrecognizedKind(kind) => {
                return Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
            }
        };

        Ok(unwind_result)
    }
}
