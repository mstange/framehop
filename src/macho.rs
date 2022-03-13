use std::marker::PhantomData;

use crate::dwarf::DwarfUnwinderError;
use crate::{arch::Arch, unwind_rule::UnwindRule};
use macho_unwind_info::UnwindInfo;

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

    #[error("rbp offset from the stack pointer divided by 8 does not fit into i16")]
    BpOffsetDoesNotFit,

    #[error("Unrecognized __unwind_info opcode kind {0}")]
    BadOpcodeKind(u8),

    #[error("DWARF unwinding failed: {0}")]
    BadDwarfUnwinding(#[from] DwarfUnwinderError),

    #[error("Encountered frameless function with indirect stack offset, TODO")]
    CantHandleFramelessIndirect,

    #[error("Encountered invalid unwind entry")]
    InvalidFrameless,
}

#[derive(Clone, Debug)]
pub struct CuiUnwindResult<R: UnwindRule> {
    pub result: CuiUnwindResult2<R>,
    /// for prologue / epilogue analysis
    /// Only non-empty for the first frame
    pub function_info: Option<FunctionInfo>,
}

impl<R: UnwindRule> CuiUnwindResult<R> {
    pub fn exec_rule(rule: R) -> Self {
        Self {
            result: CuiUnwindResult2::ExecRule(rule),
            function_info: None,
        }
    }

    pub fn use_dwarf(eh_frame_fde: u32) -> Self {
        Self {
            result: CuiUnwindResult2::NeedDwarf(eh_frame_fde),
            function_info: None,
        }
    }
    pub fn analyze_leaf_and_exec_rule(function_info: FunctionInfo, rule: R) -> Self {
        Self {
            result: CuiUnwindResult2::ExecRule(rule),
            function_info: Some(function_info),
        }
    }

    pub fn analyze_leaf_and_use_dwarf(function_info: FunctionInfo, eh_frame_fde: u32) -> Self {
        Self {
            result: CuiUnwindResult2::NeedDwarf(eh_frame_fde),
            function_info: Some(function_info),
        }
    }
}

#[derive(Clone, Debug)]
pub enum CuiUnwindResult2<R: UnwindRule> {
    ExecRule(R),
    NeedDwarf(u32),
}

#[derive(Clone, Debug)]
pub struct FunctionInfo {
    pub function_start: u32,
    pub function_end: u32,
}

pub trait CompactUnwindInfoUnwinding: Arch {
    fn unwind_frame(
        function: macho_unwind_info::Function,
        is_first_frame: bool,
    ) -> Result<CuiUnwindResult<Self::UnwindRule>, CompactUnwindInfoUnwinderError>;
}

pub struct CompactUnwindInfoUnwinder<'a, A: CompactUnwindInfoUnwinding> {
    unwind_info_data: &'a [u8],
    _arch: PhantomData<A>,
}

impl<'a, A: CompactUnwindInfoUnwinding> CompactUnwindInfoUnwinder<'a, A> {
    pub fn new(unwind_info_data: &'a [u8]) -> Self {
        Self {
            unwind_info_data,
            _arch: PhantomData,
        }
    }

    pub fn function_for_address(
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

    pub fn unwind_frame(
        &mut self,
        rel_lookup_address: u32,
        is_first_frame: bool,
    ) -> Result<CuiUnwindResult<A::UnwindRule>, CompactUnwindInfoUnwinderError> {
        let function = match self.function_for_address(rel_lookup_address) {
            Ok(f) => f,
            Err(CompactUnwindInfoUnwinderError::AddressOutsideRange(_)) if is_first_frame => {
                // pc is falling into this module's address range, but it's not covered by __unwind_info.
                // This could mean that we're inside a stub function, in the __stubs section.
                // All stub functions are frameless.
                // TODO: Obtain the actual __stubs address range and do better checking here.
                return Ok(CuiUnwindResult::exec_rule(
                    A::UnwindRule::rule_for_stub_functions(),
                ));
            }
            Err(err) => return Err(err),
        };
        if is_first_frame && rel_lookup_address == function.start_address {
            return Ok(CuiUnwindResult::exec_rule(
                A::UnwindRule::rule_for_function_start(),
            ));
        }
        <A as CompactUnwindInfoUnwinding>::unwind_frame(function, is_first_frame)
    }
}
