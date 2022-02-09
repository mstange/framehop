#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DwarfUnwinderError {
    #[error("Could not get the FDE for the supplied offset: {0}")]
    FdeFromOffsetFailed(#[source] gimli::Error),

    #[error("Could not find DWARF unwind info for the requested address: {0}")]
    UnwindInfoForAddressFailed(#[source] gimli::Error),

    #[error("Stack pointer moved backwards")]
    StackPointerMovedBackwards,

    #[error("Did not advance")]
    DidNotAdvance,

    #[error("Could not recover the CFA")]
    CouldNotRecoverCfa,

    #[error("Could not recover the return address")]
    CouldNotRecoverReturnAddress,

    #[error("Could not recover the frame pointer")]
    CouldNotRecoverFramePointer,
}

#[derive(Clone, Debug)]
pub enum ConversionError {
    CfaIsExpression,
    CfaIsOffsetFromUnknownRegister,
    SpOffsetDoesNotFit,
    RegisterNotStoredRelativeToCfa,
    RestoringFpButNotLr,
    LrStorageOffsetDoesNotFit,
    FpStorageOffsetDoesNotFit,
    SpOffsetFromFpDoesNotFit,
    FramePointerRuleDoesNotRestoreLr,
    FramePointerRuleDoesNotRestoreFp,
    FramePointerRuleDoesNotRestoreBp,
    FramePointerRuleHasStrangeBpOffset,
}
