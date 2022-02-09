use gimli::Reader;

use super::super::DwarfUnwinder;
use super::CompactUnwindInfoUnwinderError;
use crate::rules::UnwindRule;
use crate::unwind_result::UnwindResult;
use crate::unwinders::DwarfUnwinding;
use macho_unwind_info::UnwindInfo;

pub trait CompactUnwindInfoUnwinding: DwarfUnwinding {
    fn unwind_first<F, R>(
        opcode: u32,
        regs: &mut Self::UnwindRegs,
        pc: u64,
        _rel_pc: u32,
        dwarf_unwinder: Option<&mut DwarfUnwinder<R, Self>>,
        read_mem: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, CompactUnwindInfoUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader;

    fn unwind_next<F, R>(
        opcode: u32,
        regs: &mut Self::UnwindRegs,
        return_address: u64,
        dwarf_unwinder: Option<&mut DwarfUnwinder<R, Self>>,
        read_mem: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, CompactUnwindInfoUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader;
}

pub struct CompactUnwindInfoUnwinder<'a: 'c, 'u, 'c, R: Reader, A: CompactUnwindInfoUnwinding> {
    unwind_info_data: &'a [u8],
    dwarf_unwinder: Option<&'u mut DwarfUnwinder<'c, R, A>>,
}

impl<'a: 'c, 'u, 'c, R: Reader, A: CompactUnwindInfoUnwinding>
    CompactUnwindInfoUnwinder<'a, 'u, 'c, R, A>
{
    pub fn new(
        unwind_info_data: &'a [u8],
        dwarf_unwinder: Option<&'u mut DwarfUnwinder<'c, R, A>>,
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
        regs: &mut A::UnwindRegs,
        pc: u64,
        rel_pc: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<A::UnwindRule>, CompactUnwindInfoUnwinderError>
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
                return Ok(UnwindResult::ExecRule(
                    A::UnwindRule::rule_for_stub_functions(),
                ));
            }
            Err(err) => return Err(err),
        };
        if rel_pc == function.start_address {
            return Ok(UnwindResult::ExecRule(
                A::UnwindRule::rule_for_function_start(),
            ));
        }
        <A as CompactUnwindInfoUnwinding>::unwind_first(
            function.opcode,
            regs,
            pc,
            rel_pc,
            self.dwarf_unwinder.as_deref_mut(),
            read_mem,
        )
    }

    pub fn unwind_next<F>(
        &mut self,
        regs: &mut A::UnwindRegs,
        return_address: u64,
        rel_ra: u32,
        read_mem: &mut F,
    ) -> Result<UnwindResult<A::UnwindRule>, CompactUnwindInfoUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let function = self.function_for_address(rel_ra - 1)?;
        <A as CompactUnwindInfoUnwinding>::unwind_next(
            function.opcode,
            regs,
            return_address,
            self.dwarf_unwinder.as_deref_mut(),
            read_mem,
        )
    }
}
