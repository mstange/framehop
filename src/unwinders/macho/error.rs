use super::super::{DwarfUnwinderError, FramepointerUnwinderError};

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactUnwindInfoUnwinderError {
    #[error("Bad __unwind_info format: {0}")]
    BadFormat(#[from] macho_unwind_info::Error),

    #[error("Address 0x{0:x} outside of the range covered by __unwind_info")]
    AddressOutsideRange(u32),

    #[error("Encountered a non-leaf function which was marked as frameless.")]
    CallerCannotBeFrameless,

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
