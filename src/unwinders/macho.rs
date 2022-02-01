use gimli::Reader;

use super::{
    DwarfUnwinder, DwarfUnwinderError, FramepointerUnwinderArm64, FramepointerUnwinderError,
};
use crate::unwindregs::UnwindRegsArm64;
use macho_unwind_info::opcodes::OpcodeArm64;
use macho_unwind_info::UnwindInfo;

pub struct CompactUnwindInfoUnwinder<'a: 'c, 'u, 'c, R: Reader> {
    unwind_info_data: &'a [u8],
    dwarf_unwinder: Option<&'u mut DwarfUnwinder<'c, R>>,
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactUnwindInfoUnwinderError {
    #[error("Bad __unwind_info format: {0}")]
    BadFormat(#[from] macho_unwind_info::Error),

    #[error("Address outside of the range covered by __unwind_info")]
    AddressOutsideRange,

    #[error("No LR register value when trying to unwind frameless function")]
    MissingLrValue,

    #[error("No unwind info (null opcode) for this function in __unwind_info")]
    FunctionHasNoInfo,

    #[error("Unrecognized __unwind_info opcode kind {0}")]
    BadOpcodeKind(u8),

    #[error("Needed DWARF unwinder but didn't have one")]
    NoDwarfUnwinder,

    #[error("DWARF unwinding failed: {0}")]
    BadDwarfUnwinding(#[from] DwarfUnwinderError),

    #[error("Framepointer unwinding failed: {0}")]
    BadFramepointerUnwinding(#[from] FramepointerUnwinderError),
}

impl<'a: 'c, 'u, 'c, R: Reader> CompactUnwindInfoUnwinder<'a, 'u, 'c, R> {
    pub fn new(
        unwind_info_data: &'a [u8],
        dwarf_unwinder: Option<&'u mut DwarfUnwinder<'c, R>>,
    ) -> Self {
        Self {
            unwind_info_data,
            dwarf_unwinder,
        }
    }

    pub fn unwind_one_frame_from_pc<F>(
        &mut self,
        regs: &mut UnwindRegsArm64,
        pc: u64,
        rel_pc: u32,
        read_stack: &mut F,
    ) -> Result<u64, CompactUnwindInfoUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let unwind_info = UnwindInfo::parse(self.unwind_info_data)
            .map_err(CompactUnwindInfoUnwinderError::BadFormat)?;
        let function = unwind_info
            .lookup(rel_pc)
            .map_err(CompactUnwindInfoUnwinderError::BadFormat)?;
        let function = function.ok_or(CompactUnwindInfoUnwinderError::AddressOutsideRange)?;
        let opcode = OpcodeArm64::parse(function.opcode);
        let return_address = match opcode {
            OpcodeArm64::Null => {
                match regs.unmasked_lr() {
                    Some(lr) if lr != pc => lr,
                    _ => return Err(CompactUnwindInfoUnwinderError::FunctionHasNoInfo),
                }
            }
            OpcodeArm64::Frameless {
                stack_size_in_bytes,
            } => {
                regs.sp = regs.sp.map(|sp| sp + stack_size_in_bytes as u64);
                regs.unmasked_lr().ok_or(CompactUnwindInfoUnwinderError::MissingLrValue)?
            }
            OpcodeArm64::Dwarf { eh_frame_fde } => {
                let dwarf_unwinder = self.dwarf_unwinder.as_mut().ok_or(CompactUnwindInfoUnwinderError::NoDwarfUnwinder)?;
                        dwarf_unwinder
                            .unwind_one_frame_from_pc_with_fde(regs, pc, eh_frame_fde, read_stack)?
            }
            OpcodeArm64::FrameBased {
                //saved_reg_pair_count,
                ..
            } => {
                // Each pair takes one 4-byte instruction to save or restore. fp gets updated after saving or before restoring.
                // Use this to do something smart for prologues / epilogues.
                // let prologue_end = function.start_address +
                //     saved_reg_pair_count as u32 * 4 + // 4 bytes per pair
                //     4 + // save fp and lr
                //     4; // set fp to the new value
                // let epilogue_start = function.end_address -
                //    4 - // restore fp and lr
                //    saved_reg_pair_count as u32 * 4 - // 4 bytes per pair
                //    4; // ret
                FramepointerUnwinderArm64.unwind_one_frame(regs, read_stack)?
            },
            OpcodeArm64::UnrecognizedKind(kind) => return Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
        };

        Ok(return_address)
    }
}
