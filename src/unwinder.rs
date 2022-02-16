use fallible_iterator::FallibleIterator;
use gimli::{EndianReader, LittleEndian};

use crate::arcdata::ArcData;
use crate::arch::Arch;
use crate::cache::{AllocationPolicy, Cache};
use crate::dwarf::{DwarfUnwinder, DwarfUnwinding};
use crate::error::{Error, UnwinderError};
use crate::macho::{CompactUnwindInfoUnwinder, CompactUnwindInfoUnwinding, CuiUnwindResult};
use crate::rule_cache::CacheResult;
use crate::unwind_result::UnwindResult;
use crate::unwind_rule::UnwindRule;
use crate::CodeAddress;

use std::marker::PhantomData;
use std::{
    fmt::Debug,
    ops::{Deref, Range},
    sync::Arc,
};
pub trait Unwinder {
    type UnwindRegs;
    type Cache;
    type Module;

    fn add_module(&mut self, module: Self::Module);

    fn remove_module(&mut self, module_address_range_start: u64);

    fn unwind_first<F>(
        &self,
        pc: u64,
        regs: &mut Self::UnwindRegs,
        cache: &mut Self::Cache,
        read_mem: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>;

    fn unwind_next<F>(
        &self,
        return_address: u64,
        regs: &mut Self::UnwindRegs,
        cache: &mut Self::Cache,
        read_mem: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>;

    fn iter_frames<'u, 'c, 'r, F>(
        &'u self,
        pc: u64,
        regs: Self::UnwindRegs,
        cache: &'c mut Self::Cache,
        read_mem: &'r mut F,
    ) -> UnwindIterator<'u, 'c, 'r, Self, F>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        UnwindIterator::new(self, pc, regs, cache, read_mem)
    }
}

pub struct UnwindIterator<'u, 'c, 'r, U: Unwinder + ?Sized, F: FnMut(u64) -> Result<u64, ()>> {
    unwinder: &'u U,
    state: UnwindIteratorState,
    regs: U::UnwindRegs,
    cache: &'c mut U::Cache,
    read_mem: &'r mut F,
}

enum UnwindIteratorState {
    Initial(u64),
    ReadyForFirstUnwind(u64),
    ReadyForNextUnwind(u64),
    Done,
}

impl<'u, 'c, 'r, U: Unwinder + ?Sized, F: FnMut(u64) -> Result<u64, ()>>
    UnwindIterator<'u, 'c, 'r, U, F>
{
    pub fn new(
        unwinder: &'u U,
        pc: u64,
        regs: U::UnwindRegs,
        cache: &'c mut U::Cache,
        read_mem: &'r mut F,
    ) -> Self {
        Self {
            unwinder,
            state: UnwindIteratorState::Initial(pc),
            regs,
            cache,
            read_mem,
        }
    }
}

impl<'u, 'c, 'r, U: Unwinder + ?Sized, F: FnMut(u64) -> Result<u64, ()>> FallibleIterator
    for UnwindIterator<'u, 'c, 'r, U, F>
{
    type Item = u64;
    type Error = Error;

    fn next(&mut self) -> Result<Option<u64>, Error> {
        let next =
            match self.state {
                UnwindIteratorState::Initial(pc) => {
                    self.state = UnwindIteratorState::ReadyForFirstUnwind(pc);
                    return Ok(Some(pc));
                }
                UnwindIteratorState::ReadyForFirstUnwind(pc) => {
                    self.unwinder
                        .unwind_first(pc, &mut self.regs, self.cache, self.read_mem)?
                }
                UnwindIteratorState::ReadyForNextUnwind(return_address) => self
                    .unwinder
                    .unwind_next(return_address, &mut self.regs, self.cache, self.read_mem)?,
                UnwindIteratorState::Done => return Ok(None),
            };
        match next {
            Some(return_address) => {
                self.state = UnwindIteratorState::ReadyForNextUnwind(return_address);
            }
            None => {
                self.state = UnwindIteratorState::Done;
            }
        }
        Ok(next)
    }
}

pub struct UnwinderInternal<
    D: Deref<Target = [u8]>,
    A: Arch + DwarfUnwinding + CompactUnwindInfoUnwinding,
    P: AllocationPolicy<D>,
> {
    /// sorted by address_range.start
    modules: Vec<Module<D>>,
    /// Incremented every time modules is changed.
    modules_generation: u16,
    _arch: PhantomData<A>,
    _allocation_policy: PhantomData<P>,
}

impl<
        D: Deref<Target = [u8]>,
        A: Arch + DwarfUnwinding + CompactUnwindInfoUnwinding,
        P: AllocationPolicy<D>,
    > Default for UnwinderInternal<D, A, P>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
        D: Deref<Target = [u8]>,
        A: Arch + DwarfUnwinding + CompactUnwindInfoUnwinding,
        P: AllocationPolicy<D>,
    > UnwinderInternal<D, A, P>
{
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            modules_generation: 0,
            _arch: PhantomData,
            _allocation_policy: PhantomData,
        }
    }

    pub fn add_module(&mut self, module: Module<D>) {
        let insertion_index = match self
            .modules
            .binary_search_by_key(&module.address_range.start, |module| {
                module.address_range.start
            }) {
            Ok(i) => {
                eprintln!(
                    "Now we have two modules at the same start address 0x{:x}. This can't be good.",
                    module.address_range.start
                );
                i
            }
            Err(i) => i,
        };
        self.modules.insert(insertion_index, module);
        self.modules_generation += 1;
    }

    pub fn remove_module(&mut self, module_address_range_start: u64) {
        if let Ok(index) = self
            .modules
            .binary_search_by_key(&module_address_range_start, |module| {
                module.address_range.start
            })
        {
            self.modules.remove(index);
            self.modules_generation += 1;
        };
    }

    fn find_module_for_address(&self, pc: u64) -> Option<usize> {
        let module_index = match self
            .modules
            .binary_search_by_key(&pc, |m| m.address_range.start)
        {
            Ok(i) => i,
            Err(insertion_index) => {
                if insertion_index == 0 {
                    // pc is before first known module
                    return None;
                }
                let i = insertion_index - 1;
                if self.modules[i].address_range.end <= pc {
                    // pc is after this module
                    return None;
                }
                i
            }
        };
        Some(module_index)
    }

    fn with_cache<F, G>(
        &self,
        address: CodeAddress,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule, P>,
        read_mem: &mut F,
        callback: G,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        G: FnOnce(
            &Module<D>,
            u64,
            &mut A::UnwindRegs,
            &mut Cache<D, A::UnwindRule, P>,
            &mut F,
        ) -> Result<UnwindResult<A::UnwindRule>, UnwinderError>,
    {
        let lookup_address = address.address_for_lookup();
        let cache_handle = match cache.rule_cache.try_unwind(
            lookup_address,
            self.modules_generation,
            regs,
            read_mem,
        ) {
            CacheResult::Hit(result) => return result,
            CacheResult::Miss(handle) => handle,
        };

        let unwind_rule = match self.find_module_for_address(lookup_address) {
            None => A::UnwindRule::fallback_rule(),
            Some(module_index) => {
                let module = &self.modules[module_index];
                match callback(module, address.address(), regs, cache, read_mem) {
                    Ok(UnwindResult::ExecRule(rule)) => rule,
                    Ok(UnwindResult::Uncacheable(return_address)) => {
                        return Ok(Some(return_address))
                    }
                    Err(_err) => {
                        // eprintln!("Unwinder error: {}", err);
                        A::UnwindRule::fallback_rule()
                    }
                }
            }
        };
        cache.rule_cache.insert(cache_handle, unwind_rule);
        unwind_rule.exec(regs, read_mem)
    }

    pub fn unwind_first<F>(
        &self,
        pc: u64,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule, P>,
        read_mem: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        // eprintln!("unwind_first for {:x}", pc);
        self.with_cache(
            CodeAddress::InstructionPointer(pc),
            regs,
            cache,
            read_mem,
            Self::unwind_first_impl,
        )
    }

    pub fn unwind_next<F>(
        &self,
        return_address: u64,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule, P>,
        read_mem: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        // eprintln!("unwind_next for {:x}", return_address);
        self.with_cache(
            CodeAddress::ReturnAddress(return_address),
            regs,
            cache,
            read_mem,
            Self::unwind_next_impl,
        )
    }

    fn unwind_first_impl<F>(
        module: &Module<D>,
        pc: u64,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule, P>,
        read_mem: &mut F,
    ) -> Result<UnwindResult<A::UnwindRule>, UnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let rel_pc = (pc - module.base_address) as u32;

        let unwind_result = match &module.unwind_data {
            ModuleUnwindData::CompactUnwindInfoAndEhFrame(unwind_data, eh_frame_data) => {
                // eprintln!("unwinding with cui and eh_frame in module {}", module.name);
                let mut unwinder = CompactUnwindInfoUnwinder::<A>::new(&unwind_data[..]);
                match unwinder.unwind_first(regs, pc, rel_pc, read_mem) {
                    CuiUnwindResult::ExecRule(rule) => UnwindResult::ExecRule(rule),
                    CuiUnwindResult::Uncacheable(return_address) => {
                        UnwindResult::Uncacheable(return_address)
                    }
                    CuiUnwindResult::NeedDwarf(fde_offset) => {
                        let eh_frame_data = match eh_frame_data {
                            Some(data) => ArcData(data.clone()),
                            None => return Err(UnwinderError::NoDwarfData),
                        };
                        let mut dwarf_unwinder = DwarfUnwinder::<_, A, P::GimliStorage>::new(
                            EndianReader::new(eh_frame_data, LittleEndian),
                            None,
                            &mut cache.eh_frame_unwind_context,
                            &module.sections,
                        );
                        dwarf_unwinder.unwind_first_with_fde(regs, pc, fde_offset, read_mem)?
                    }
                    CuiUnwindResult::Err(err) => return Err(err.into()),
                }
            }
            ModuleUnwindData::EhFrameHdrAndEhFrame(eh_frame_hdr, eh_frame_data) => {
                let eh_frame_hdr_data = ArcData(eh_frame_hdr.clone());
                let eh_frame_data = ArcData(eh_frame_data.clone());
                let mut dwarf_unwinder = DwarfUnwinder::<_, A, P::GimliStorage>::new(
                    EndianReader::new(eh_frame_data, LittleEndian),
                    Some(EndianReader::new(eh_frame_hdr_data, LittleEndian)),
                    &mut cache.eh_frame_unwind_context,
                    &module.sections,
                );
                let fde_offset = dwarf_unwinder
                    .get_fde_offset_for_address(pc)
                    .ok_or(UnwinderError::EhFrameHdrCouldNotFindAddress)?;
                dwarf_unwinder.unwind_first_with_fde(regs, pc, fde_offset, read_mem)?
            }
            ModuleUnwindData::EhFrame(_) => {
                return Err(UnwinderError::UnhandledModuleUnwindDataType)
            }
            ModuleUnwindData::None => return Err(UnwinderError::NoModuleUnwindData),
        };
        Ok(unwind_result)
    }

    fn unwind_next_impl<F>(
        module: &Module<D>,
        return_address: u64,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule, P>,
        read_mem: &mut F,
    ) -> Result<UnwindResult<A::UnwindRule>, UnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let rel_ra = (return_address - module.base_address) as u32;

        // eprintln!(
        //     "Unwinding at ra {} + 0x{:x} (= 0x{:x}) with regs {:?}",
        //     self.name, rel_ra, return_address, regs
        // );
        let unwind_result = match &module.unwind_data {
            ModuleUnwindData::CompactUnwindInfoAndEhFrame(unwind_data, eh_frame_data) => {
                // eprintln!("unwinding with cui and eh_frame in module {}", module.name);
                let mut unwinder = CompactUnwindInfoUnwinder::<A>::new(&unwind_data[..]);
                match unwinder.unwind_next(regs, rel_ra, read_mem) {
                    CuiUnwindResult::ExecRule(rule) => UnwindResult::ExecRule(rule),
                    CuiUnwindResult::Uncacheable(return_address) => {
                        UnwindResult::Uncacheable(return_address)
                    }
                    CuiUnwindResult::NeedDwarf(fde_offset) => {
                        let eh_frame_data = match eh_frame_data {
                            Some(data) => ArcData(data.clone()),
                            None => return Err(UnwinderError::NoDwarfData),
                        };
                        let mut dwarf_unwinder = DwarfUnwinder::<_, A, P::GimliStorage>::new(
                            EndianReader::new(eh_frame_data, LittleEndian),
                            None,
                            &mut cache.eh_frame_unwind_context,
                            &module.sections,
                        );
                        dwarf_unwinder.unwind_next_with_fde(
                            regs,
                            return_address,
                            fde_offset,
                            read_mem,
                        )?
                    }
                    CuiUnwindResult::Err(err) => return Err(err.into()),
                }
            }
            ModuleUnwindData::EhFrameHdrAndEhFrame(eh_frame_hdr, eh_frame_data) => {
                let eh_frame_hdr_data = ArcData(eh_frame_hdr.clone());
                let eh_frame_data = ArcData(eh_frame_data.clone());
                let mut dwarf_unwinder = DwarfUnwinder::<_, A, P::GimliStorage>::new(
                    EndianReader::new(eh_frame_data, LittleEndian),
                    Some(EndianReader::new(eh_frame_hdr_data, LittleEndian)),
                    &mut cache.eh_frame_unwind_context,
                    &module.sections,
                );
                let fde_offset = dwarf_unwinder
                    .get_fde_offset_for_address(return_address - 1)
                    .ok_or(UnwinderError::EhFrameHdrCouldNotFindAddress)?;
                dwarf_unwinder.unwind_first_with_fde(regs, return_address, fde_offset, read_mem)?
            }
            ModuleUnwindData::EhFrame(_) => {
                return Err(UnwinderError::UnhandledModuleUnwindDataType)
            }
            ModuleUnwindData::None => return Err(UnwinderError::NoModuleUnwindData),
        };
        Ok(unwind_result)
    }
}

pub enum ModuleUnwindData<D: Deref<Target = [u8]>> {
    CompactUnwindInfoAndEhFrame(D, Option<Arc<D>>),
    EhFrameHdrAndEhFrame(Arc<D>, Arc<D>),
    EhFrame(Arc<D>),
    None,
}

pub struct Module<D: Deref<Target = [u8]>> {
    #[allow(unused)]
    name: String,
    address_range: Range<u64>,
    base_address: u64,
    #[allow(unused)]
    vm_addr_at_base_addr: u64,
    sections: ModuleSectionAddresses,
    unwind_data: ModuleUnwindData<D>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSectionAddresses {
    pub text: u64,
    pub eh_frame: u64,
    pub eh_frame_hdr: u64,
    pub got: u64,
}

impl<D: Deref<Target = [u8]>> Debug for Module<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Module")
            .field("name", &self.name)
            .field("address_range", &self.address_range)
            .finish()
    }
}

impl<D: Deref<Target = [u8]>> Module<D> {
    pub fn new(
        name: String,
        address_range: std::ops::Range<u64>,
        base_address: u64,
        vm_addr_at_base_addr: u64,
        sections: ModuleSectionAddresses,
        unwind_data: ModuleUnwindData<D>,
    ) -> Self {
        Self {
            name,
            address_range,
            base_address,
            vm_addr_at_base_addr,
            sections,
            unwind_data,
        }
    }
}
