use gimli::Reader;

use super::super::{DwarfUnwinder, FramepointerUnwinderArm64};
use super::CompactUnwindInfoUnwinderError;
use crate::arch::ArchArm64;
use crate::rules::UnwindRuleArm64;
use crate::unwind_result::UnwindResult;
use crate::unwindregs::UnwindRegsArm64;
use macho_unwind_info::opcodes::OpcodeArm64;
use macho_unwind_info::UnwindInfo;

pub struct CompactUnwindInfoUnwinder<'a: 'c, 'u, 'c, R: Reader> {
    unwind_info_data: &'a [u8],
    dwarf_unwinder: Option<&'u mut DwarfUnwinder<'c, R, ArchArm64>>,
}

impl<'a: 'c, 'u, 'c, R: Reader> CompactUnwindInfoUnwinder<'a, 'u, 'c, R> {
    pub fn new(
        unwind_info_data: &'a [u8],
        dwarf_unwinder: Option<&'u mut DwarfUnwinder<'c, R, ArchArm64>>,
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
        regs: &mut UnwindRegsArm64,
        pc: u64,
        rel_pc: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<UnwindRuleArm64>, CompactUnwindInfoUnwinderError>
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
                return Ok(UnwindResult::ExecRule(UnwindRuleArm64::NoOp));
            }
            Err(err) => return Err(err),
        };
        if rel_pc == function.start_address {
            return Ok(UnwindResult::ExecRule(UnwindRuleArm64::NoOp));
        }

        let opcode = OpcodeArm64::parse(function.opcode);
        let unwind_result = match opcode {
            OpcodeArm64::Null => UnwindResult::ExecRule(UnwindRuleArm64::NoOp),
            OpcodeArm64::Frameless {
                stack_size_in_bytes,
            } => {
                if stack_size_in_bytes == 0 {
                    UnwindResult::ExecRule(UnwindRuleArm64::NoOp)
                } else {
                    match u8::try_from(stack_size_in_bytes / 16) {
                        Ok(sp_offset_by_16) => {
                            UnwindResult::ExecRule(UnwindRuleArm64::OffsetSp { sp_offset_by_16 })
                        }
                        Err(_) => {
                            eprintln!("Uncacheable rule in compact unwind info unwinder because Frameless stack size doesn't fit");
                            regs.set_sp(regs.sp() + stack_size_in_bytes as u64);
                            UnwindResult::Uncacheable(regs.lr())
                        }
                    }
                }
            }
            OpcodeArm64::Dwarf { eh_frame_fde } => {
                let dwarf_unwinder = self
                    .dwarf_unwinder
                    .as_mut()
                    .ok_or(CompactUnwindInfoUnwinderError::NoDwarfUnwinder)?;
                dwarf_unwinder.unwind_first_with_fde(regs, pc, eh_frame_fde, read_mem)?
            }
            OpcodeArm64::FrameBased { .. } => {
                // Each pair takes one 4-byte instruction to save or restore. fp gets updated after saving or before restoring.
                // Use this to do something smart for prologues / epilogues.
                // let prologue_end = function.start_address +
                //         saved_reg_pair_count as u32 * 4 + // 4 bytes per pair
                //         4 + // save fp and lr
                //         4; // set fp to the new value
                // if rel_pc < prologue_end {
                //     // TODO: Disassemble instructions from the beginning to see how deep we are into the stack.
                //     FramepointerUnwinderArm64.unwind_next(regs, read_mem)?

                // TODO: Detect if we're in an epilogue, by seeing if the current instruction restores
                // registers from the stack (and then keep reading) or is a return instruction.
                FramepointerUnwinderArm64.unwind_first()?
            }
            OpcodeArm64::UnrecognizedKind(kind) => {
                return Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
            }
        };

        Ok(unwind_result)
    }

    pub fn unwind_next<F>(
        &mut self,
        regs: &mut UnwindRegsArm64,
        return_address: u64,
        rel_ra: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<UnwindRuleArm64>, CompactUnwindInfoUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let function = self.function_for_address(rel_ra - 1)?;
        let opcode = OpcodeArm64::parse(function.opcode);
        let unwind_result = match opcode {
            OpcodeArm64::Null => {
                return Err(CompactUnwindInfoUnwinderError::FunctionHasNoInfo);
            }
            OpcodeArm64::Frameless { .. } => {
                return Err(CompactUnwindInfoUnwinderError::CallerCannotBeFrameless);
            }
            OpcodeArm64::Dwarf { eh_frame_fde } => {
                let dwarf_unwinder = self
                    .dwarf_unwinder
                    .as_mut()
                    .ok_or(CompactUnwindInfoUnwinderError::NoDwarfUnwinder)?;
                dwarf_unwinder.unwind_next_with_fde(regs, return_address, eh_frame_fde, read_mem)?
            }
            OpcodeArm64::FrameBased { .. } => {
                UnwindResult::ExecRule(UnwindRuleArm64::UseFramePointer)
            }
            OpcodeArm64::UnrecognizedKind(kind) => {
                return Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
            }
        };

        Ok(unwind_result)
    }
}
