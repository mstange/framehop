use super::super::DwarfUnwinderError;

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

    #[error("DWARF unwinding failed: {0}")]
    BadDwarfUnwinding(#[from] DwarfUnwinderError),

    #[error("Encountered frameless function with indirect stack offset, TODO")]
    CantHandleFramelessIndirect,

    #[error("Encountered invalid unwind entry")]
    InvalidFramelessImmediate,

    #[error("Could not read return address from stack")]
    CouldNotReadReturnAddress,

    #[error("Could not restore bp register from stack")]
    CouldNotReadBp,
}
