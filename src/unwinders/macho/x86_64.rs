use gimli::Reader;

use super::super::{DwarfUnwinder, DwarfUnwinderX86_64, FramepointerUnwinderX86_64};
use super::CompactUnwindInfoUnwinderError;
use crate::rules::UnwindRuleX86_64;
use crate::unwind_result::UnwindResult;
use crate::unwindregs::UnwindRegsX86_64;
use macho_unwind_info::opcodes::{OpcodeX86_64, RegisterNameX86_64};
use macho_unwind_info::UnwindInfo;

pub struct CompactUnwindInfoUnwinderX86_46<'a: 'c, 'u, 'c, R: Reader> {
    unwind_info_data: &'a [u8],
    dwarf_unwinder: Option<&'u mut DwarfUnwinderX86_64<'c, R>>,
}

impl<'a: 'c, 'u, 'c, R: Reader> CompactUnwindInfoUnwinderX86_46<'a, 'u, 'c, R> {
    pub fn new(
        unwind_info_data: &'a [u8],
        dwarf_unwinder: Option<&'u mut DwarfUnwinderX86_64<'c, R>>,
    ) -> Self {
        Self {
            unwind_info_data,
            dwarf_unwinder,
        }
    }

    fn function_for_address(
        &self,
        address: u32,
    ) -> Result<macho_unwind_info::Function, CompactUnwindInfoUnwinderError> {
        let unwind_info = UnwindInfo::parse(self.unwind_info_data)
            .map_err(CompactUnwindInfoUnwinderError::BadFormat)?;
        let function = unwind_info
            .lookup(address)
            .map_err(CompactUnwindInfoUnwinderError::BadFormat)?;
        function.ok_or(CompactUnwindInfoUnwinderError::AddressOutsideRange(address))
    }

    pub fn unwind_first<F>(
        &mut self,
        regs: &mut UnwindRegsX86_64,
        pc: u64,
        rel_pc: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<UnwindRuleX86_64>, CompactUnwindInfoUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let function = match self.function_for_address(rel_pc) {
            Ok(f) => f,
            Err(CompactUnwindInfoUnwinderError::AddressOutsideRange(_)) => {
                // pc is falling into this module's address range, but it's not covered by __unwind_info.
                // This could mean that we're inside a stub function, in the __stubs section.
                // All stub functions are frameless.
                // TODO: Obtain the actual __stubs address range and do better checking here.
                return Ok(UnwindResult::ExecRule(UnwindRuleX86_64::JustReturn));
            }
            Err(err) => return Err(err),
        };
        if rel_pc == function.start_address {
            return Ok(UnwindResult::ExecRule(UnwindRuleX86_64::JustReturn));
        }

        let opcode = OpcodeX86_64::parse(function.opcode);
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
                let dwarf_unwinder = self
                    .dwarf_unwinder
                    .as_mut()
                    .ok_or(CompactUnwindInfoUnwinderError::NoDwarfUnwinder)?;
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

    pub fn unwind_next<F>(
        &mut self,
        regs: &mut UnwindRegsX86_64,
        return_address: u64,
        rel_ra: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<UnwindRuleX86_64>, CompactUnwindInfoUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let function = self.function_for_address(rel_ra - 1)?;
        let opcode = OpcodeX86_64::parse(function.opcode);
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
                let dwarf_unwinder = self
                    .dwarf_unwinder
                    .as_mut()
                    .ok_or(CompactUnwindInfoUnwinderError::NoDwarfUnwinder)?;
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
