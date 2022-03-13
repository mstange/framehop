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

    #[error("Don't have the function bytes to look up the offset for frameless function with indirect stack offset")]
    NoTextBytesToLookUpIndirectStackOffset,

    #[error("Stack offset not found inside the bounds of the text bytes")]
    IndirectStackOffsetOutOfBounds,

    #[error("Stack adjust addition overflowed")]
    StackAdjustOverflow,

    #[error("Stack size does not fit into the rule representation")]
    StackSizeDoesNotFit,

    #[error("Encountered invalid unwind entry")]
    InvalidFrameless,
}

#[derive(Clone, Debug)]
pub enum CuiUnwindResult<R: UnwindRule> {
    ExecRule(R),
    NeedDwarf(u32),
}

pub trait CompactUnwindInfoUnwinding: Arch {
    fn unwind_frame(
        function: macho_unwind_info::Function,
        is_first_frame: bool,
        address_offset_within_function: usize,
        function_bytes: Option<&[u8]>,
    ) -> Result<CuiUnwindResult<Self::UnwindRule>, CompactUnwindInfoUnwinderError>;
}

#[derive(Clone, Copy)]
pub struct TextBytes<'a> {
    offset_from_base_address: u32,
    bytes: &'a [u8],
}

impl<'a> TextBytes<'a> {
    pub fn new(offset_from_base_address: u32, bytes: &'a [u8]) -> Self {
        Self {
            offset_from_base_address,
            bytes,
        }
    }
}

pub struct CompactUnwindInfoUnwinder<'a, A: CompactUnwindInfoUnwinding> {
    unwind_info_data: &'a [u8],
    text_bytes: Option<TextBytes<'a>>,
    _arch: PhantomData<A>,
}

impl<'a, A: CompactUnwindInfoUnwinding> CompactUnwindInfoUnwinder<'a, A> {
    pub fn new(unwind_info_data: &'a [u8], text_bytes: Option<TextBytes<'a>>) -> Self {
        Self {
            unwind_info_data,
            text_bytes,
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
                return Ok(CuiUnwindResult::ExecRule(
                    A::UnwindRule::rule_for_stub_functions(),
                ));
            }
            Err(err) => return Err(err),
        };
        if is_first_frame && rel_lookup_address == function.start_address {
            return Ok(CuiUnwindResult::ExecRule(
                A::UnwindRule::rule_for_function_start(),
            ));
        }
        let address_offset_within_function =
            usize::try_from(rel_lookup_address - function.start_address).unwrap();
        let function_bytes = self.text_bytes.and_then(|text_bytes| {
            let TextBytes {
                offset_from_base_address,
                bytes,
            } = text_bytes;
            let function_start_relative_to_text = function
                .start_address
                .checked_sub(offset_from_base_address)?
                as usize;
            let function_end_relative_to_text =
                function.end_address.checked_sub(offset_from_base_address)? as usize;
            Some(bytes.get(function_start_relative_to_text..function_end_relative_to_text)?)
        });
        <A as CompactUnwindInfoUnwinding>::unwind_frame(
            function,
            is_first_frame,
            address_offset_within_function,
            function_bytes,
        )
    }
}
