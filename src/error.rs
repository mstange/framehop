use super::unwinders::{
    CompactUnwindInfoUnwinderError, DwarfUnwinderError, FramepointerUnwinderError,
};

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("Unwinding failed")]
    UnwindingFailed,

    #[error("The end of the stack has been reached.")]
    StackEndReached,
}

impl From<FramepointerUnwinderError> for Error {
    fn from(err: FramepointerUnwinderError) -> Self {
        match err {
            FramepointerUnwinderError::FoundStackEnd => Error::StackEndReached,
            _ => Error::UnwindingFailed,
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwinderError {
    #[error("Framepointer unwinding failed: {0}")]
    FramePointer(#[from] FramepointerUnwinderError),

    #[error("Compact Unwind Info unwinding failed: {0}")]
    CompactUnwindInfo(#[source] CompactUnwindInfoUnwinderError),

    #[error("DWARF unwinding failed: {0}")]
    Dwarf(#[from] DwarfUnwinderError),
}

impl From<CompactUnwindInfoUnwinderError> for UnwinderError {
    fn from(e: CompactUnwindInfoUnwinderError) -> Self {
        match e {
            CompactUnwindInfoUnwinderError::BadDwarfUnwinding(e) => UnwinderError::Dwarf(e),
            CompactUnwindInfoUnwinderError::BadFramepointerUnwinding(e) => {
                UnwinderError::FramePointer(e)
            }
            e => UnwinderError::CompactUnwindInfo(e),
        }
    }
}
