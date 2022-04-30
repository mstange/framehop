use fallible_iterator::FallibleIterator;
use gimli::{EndianReader, LittleEndian};

use crate::arcdata::ArcData;
use crate::arch::Arch;
use crate::cache::{AllocationPolicy, Cache};
use crate::dwarf::{DwarfCfiIndex, DwarfUnwinder, DwarfUnwinding, UnwindSectionType};
use crate::error::{Error, UnwinderError};
use crate::instruction_analysis::InstructionAnalysis;
use crate::macho::{
    CompactUnwindInfoUnwinder, CompactUnwindInfoUnwinding, CuiUnwindResult, TextBytes,
};
use crate::rule_cache::CacheResult;
use crate::unwind_result::UnwindResult;
use crate::unwind_rule::UnwindRule;
use crate::FrameAddress;

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU16, Ordering};
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

    fn max_known_code_address(&self) -> u64;

    fn unwind_frame<F>(
        &self,
        address: FrameAddress,
        regs: &mut Self::UnwindRegs,
        cache: &mut Self::Cache,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>;

    fn iter_frames<'u, 'c, 'r, F>(
        &'u self,
        pc: u64,
        regs: Self::UnwindRegs,
        cache: &'c mut Self::Cache,
        read_stack: &'r mut F,
    ) -> UnwindIterator<'u, 'c, 'r, Self, F>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        UnwindIterator::new(self, pc, regs, cache, read_stack)
    }
}

pub struct UnwindIterator<'u, 'c, 'r, U: Unwinder + ?Sized, F: FnMut(u64) -> Result<u64, ()>> {
    unwinder: &'u U,
    state: UnwindIteratorState,
    regs: U::UnwindRegs,
    cache: &'c mut U::Cache,
    read_stack: &'r mut F,
}

enum UnwindIteratorState {
    Initial(u64),
    Unwinding(FrameAddress),
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
        read_stack: &'r mut F,
    ) -> Self {
        Self {
            unwinder,
            state: UnwindIteratorState::Initial(pc),
            regs,
            cache,
            read_stack,
        }
    }
}

impl<'u, 'c, 'r, U: Unwinder + ?Sized, F: FnMut(u64) -> Result<u64, ()>>
    UnwindIterator<'u, 'c, 'r, U, F>
{
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<FrameAddress>, Error> {
        let next = match self.state {
            UnwindIteratorState::Initial(pc) => {
                self.state = UnwindIteratorState::Unwinding(FrameAddress::InstructionPointer(pc));
                return Ok(Some(FrameAddress::InstructionPointer(pc)));
            }
            UnwindIteratorState::Unwinding(address) => {
                self.unwinder
                    .unwind_frame(address, &mut self.regs, self.cache, self.read_stack)?
            }
            UnwindIteratorState::Done => return Ok(None),
        };
        match next {
            Some(return_address) => {
                let return_address = FrameAddress::from_return_address(return_address)
                    .ok_or(Error::ReturnAddressIsNull)?;
                self.state = UnwindIteratorState::Unwinding(return_address);
                Ok(Some(return_address))
            }
            None => {
                self.state = UnwindIteratorState::Done;
                Ok(None)
            }
        }
    }
}

impl<'u, 'c, 'r, U: Unwinder + ?Sized, F: FnMut(u64) -> Result<u64, ()>> FallibleIterator
    for UnwindIterator<'u, 'c, 'r, U, F>
{
    type Item = FrameAddress;
    type Error = Error;

    fn next(&mut self) -> Result<Option<FrameAddress>, Error> {
        self.next()
    }
}

/// This global generation counter makes it so that the cache can be shared
/// between multiple unwinders.
/// This is a u16, so if you make it wrap around by adding / removing modules
/// more than 65535 times, then you risk collisions in the cache; meaning:
/// unwinding might not work properly if an old unwind rule was found in the
/// cache for the same address and the same (pre-wraparound) modules_generation.
static GLOBAL_MODULES_GENERATION: AtomicU16 = AtomicU16::new(0);

fn next_global_modules_generation() -> u16 {
    GLOBAL_MODULES_GENERATION.fetch_add(1, Ordering::Relaxed)
}

pub struct UnwinderInternal<
    D: Deref<Target = [u8]>,
    A: Arch + DwarfUnwinding + CompactUnwindInfoUnwinding + InstructionAnalysis,
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
        A: Arch + DwarfUnwinding + CompactUnwindInfoUnwinding + InstructionAnalysis,
        P: AllocationPolicy<D>,
    > Default for UnwinderInternal<D, A, P>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
        D: Deref<Target = [u8]>,
        A: Arch + DwarfUnwinding + CompactUnwindInfoUnwinding + InstructionAnalysis,
        P: AllocationPolicy<D>,
    > UnwinderInternal<D, A, P>
{
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            modules_generation: next_global_modules_generation(),
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
        self.modules_generation = next_global_modules_generation();
    }

    pub fn remove_module(&mut self, module_address_range_start: u64) {
        if let Ok(index) = self
            .modules
            .binary_search_by_key(&module_address_range_start, |module| {
                module.address_range.start
            })
        {
            self.modules.remove(index);
            self.modules_generation = next_global_modules_generation();
        };
    }

    pub fn max_known_code_address(&self) -> u64 {
        self.modules.last().map_or(0, |m| m.address_range.end)
    }

    fn find_module_for_address(&self, address: u64) -> Option<(usize, u32)> {
        let (module_index, module) = match self
            .modules
            .binary_search_by_key(&address, |m| m.address_range.start)
        {
            Ok(i) => (i, &self.modules[i]),
            Err(insertion_index) => {
                if insertion_index == 0 {
                    // address is before first known module
                    return None;
                }
                let i = insertion_index - 1;
                let module = &self.modules[i];
                if module.address_range.end <= address {
                    // address is after this module
                    return None;
                }
                (i, module)
            }
        };
        if address < module.base_address {
            // Invalid base address
            return None;
        }
        let relative_address = u32::try_from(address - module.base_address).ok()?;
        Some((module_index, relative_address))
    }

    fn with_cache<F, G>(
        &self,
        address: FrameAddress,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule, P>,
        read_stack: &mut F,
        callback: G,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        G: FnOnce(
            &Module<D>,
            FrameAddress,
            u32,
            &mut A::UnwindRegs,
            &mut Cache<D, A::UnwindRule, P>,
            &mut F,
        ) -> Result<UnwindResult<A::UnwindRule>, UnwinderError>,
    {
        let lookup_address = address.address_for_lookup();
        let is_first_frame = !address.is_return_address();
        let cache_handle = match cache
            .rule_cache
            .lookup(lookup_address, self.modules_generation)
        {
            CacheResult::Hit(unwind_rule) => {
                return unwind_rule.exec(is_first_frame, regs, read_stack);
            }
            CacheResult::Miss(handle) => handle,
        };

        let unwind_rule = match self.find_module_for_address(lookup_address) {
            None => A::UnwindRule::fallback_rule(),
            Some((module_index, relative_lookup_address)) => {
                let module = &self.modules[module_index];
                match callback(
                    module,
                    address,
                    relative_lookup_address,
                    regs,
                    cache,
                    read_stack,
                ) {
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
        unwind_rule.exec(is_first_frame, regs, read_stack)
    }

    pub fn unwind_frame<F>(
        &self,
        address: FrameAddress,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule, P>,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        self.with_cache(address, regs, cache, read_stack, Self::unwind_frame_impl)
    }

    fn unwind_frame_impl<F>(
        module: &Module<D>,
        address: FrameAddress,
        rel_lookup_address: u32,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule, P>,
        read_stack: &mut F,
    ) -> Result<UnwindResult<A::UnwindRule>, UnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let unwind_result = match &module.unwind_data {
            ModuleUnwindDataInternal::CompactUnwindInfoAndEhFrame(unwind_data, eh_frame_data) => {
                // eprintln!("unwinding with cui and eh_frame in module {}", module.name);
                let text_bytes = module.text_data.as_ref().and_then(|data| {
                    let offset_from_base =
                        u32::try_from(data.address_range.start.checked_sub(module.base_address)?)
                            .ok()?;
                    Some(TextBytes::new(offset_from_base, &data.bytes[..]))
                });
                let stubs_range = if let Some(stubs_range) = &module.sections.stubs {
                    (
                        (stubs_range.start - module.base_address) as u32,
                        (stubs_range.end - module.base_address) as u32,
                    )
                } else {
                    (0, 0)
                };
                let stub_helper_range =
                    if let Some(stub_helper_range) = &module.sections.stub_helper {
                        (
                            (stub_helper_range.start - module.base_address) as u32,
                            (stub_helper_range.end - module.base_address) as u32,
                        )
                    } else {
                        (0, 0)
                    };
                let mut unwinder = CompactUnwindInfoUnwinder::<A>::new(
                    &unwind_data[..],
                    text_bytes,
                    stubs_range,
                    stub_helper_range,
                );
                let is_first_frame = !address.is_return_address();

                let unwind_result = unwinder.unwind_frame(rel_lookup_address, is_first_frame)?;
                match unwind_result {
                    CuiUnwindResult::ExecRule(rule) => UnwindResult::ExecRule(rule),
                    CuiUnwindResult::NeedDwarf(fde_offset) => {
                        let eh_frame_data = match eh_frame_data {
                            Some(data) => ArcData(data.clone()),
                            None => return Err(UnwinderError::NoDwarfData),
                        };
                        let mut dwarf_unwinder = DwarfUnwinder::<_, A, P::GimliStorage>::new(
                            EndianReader::new(eh_frame_data, LittleEndian),
                            UnwindSectionType::EhFrame,
                            None,
                            &mut cache.eh_frame_unwind_context,
                            &module.sections,
                        );
                        dwarf_unwinder
                            .unwind_frame_with_fde(regs, address, fde_offset, read_stack)?
                    }
                }
            }
            ModuleUnwindDataInternal::EhFrameHdrAndEhFrame(eh_frame_hdr, eh_frame_data) => {
                let eh_frame_hdr_data = &eh_frame_hdr[..];
                let eh_frame_data = ArcData(eh_frame_data.clone());
                let mut dwarf_unwinder = DwarfUnwinder::<_, A, P::GimliStorage>::new(
                    EndianReader::new(eh_frame_data, LittleEndian),
                    UnwindSectionType::EhFrame,
                    Some(eh_frame_hdr_data),
                    &mut cache.eh_frame_unwind_context,
                    &module.sections,
                );
                let fde_offset = dwarf_unwinder
                    .get_fde_offset_for_address(address.address_for_lookup())
                    .ok_or(UnwinderError::EhFrameHdrCouldNotFindAddress)?;
                dwarf_unwinder.unwind_frame_with_fde(regs, address, fde_offset, read_stack)?
            }
            ModuleUnwindDataInternal::DwarfCfiIndexAndEhFrame(index, eh_frame_data) => {
                let eh_frame_data = ArcData(eh_frame_data.clone());
                let mut dwarf_unwinder = DwarfUnwinder::<_, A, P::GimliStorage>::new(
                    EndianReader::new(eh_frame_data, LittleEndian),
                    UnwindSectionType::EhFrame,
                    None,
                    &mut cache.eh_frame_unwind_context,
                    &module.sections,
                );
                let fde_offset = index
                    .fde_offset_for_relative_address(rel_lookup_address)
                    .ok_or(UnwinderError::DwarfCfiIndexCouldNotFindAddress)?;
                dwarf_unwinder.unwind_frame_with_fde(regs, address, fde_offset, read_stack)?
            }
            ModuleUnwindDataInternal::DwarfCfiIndexAndDebugFrame(index, debug_frame_data) => {
                let debug_frame_data = ArcData(debug_frame_data.clone());
                let mut dwarf_unwinder = DwarfUnwinder::<_, A, P::GimliStorage>::new(
                    EndianReader::new(debug_frame_data, LittleEndian),
                    UnwindSectionType::DebugFrame,
                    None,
                    &mut cache.eh_frame_unwind_context,
                    &module.sections,
                );
                let fde_offset = index
                    .fde_offset_for_relative_address(rel_lookup_address)
                    .ok_or(UnwinderError::DwarfCfiIndexCouldNotFindAddress)?;
                dwarf_unwinder.unwind_frame_with_fde(regs, address, fde_offset, read_stack)?
            }
            ModuleUnwindDataInternal::None => return Err(UnwinderError::NoModuleUnwindData),
        };
        Ok(unwind_result)
    }
}

pub enum ModuleUnwindData<D: Deref<Target = [u8]>> {
    CompactUnwindInfoAndEhFrame(D, Option<D>),
    EhFrameHdrAndEhFrame(D, D),
    EhFrame(D),
    DebugFrame(D),
    None,
}

enum ModuleUnwindDataInternal<D: Deref<Target = [u8]>> {
    CompactUnwindInfoAndEhFrame(D, Option<Arc<D>>),
    EhFrameHdrAndEhFrame(D, Arc<D>),
    DwarfCfiIndexAndEhFrame(DwarfCfiIndex, Arc<D>),
    DwarfCfiIndexAndDebugFrame(DwarfCfiIndex, Arc<D>),
    None,
}

impl<D: Deref<Target = [u8]>> ModuleUnwindDataInternal<D> {
    fn new(
        unwind_data: ModuleUnwindData<D>,
        sections: &ModuleSectionAddressRanges,
        base_address: u64,
    ) -> Self {
        match unwind_data {
            ModuleUnwindData::CompactUnwindInfoAndEhFrame(cui, eh_frame) => {
                ModuleUnwindDataInternal::CompactUnwindInfoAndEhFrame(cui, eh_frame.map(Arc::new))
            }
            ModuleUnwindData::EhFrameHdrAndEhFrame(eh_frame_hdr, eh_frame) => {
                ModuleUnwindDataInternal::EhFrameHdrAndEhFrame(eh_frame_hdr, Arc::new(eh_frame))
            }
            ModuleUnwindData::EhFrame(eh_frame) => {
                match DwarfCfiIndex::try_new_eh_frame(&eh_frame, sections, base_address) {
                    Ok(index) => {
                        ModuleUnwindDataInternal::DwarfCfiIndexAndEhFrame(index, Arc::new(eh_frame))
                    }
                    Err(_) => ModuleUnwindDataInternal::None,
                }
            }
            ModuleUnwindData::DebugFrame(debug_frame) => {
                match DwarfCfiIndex::try_new_debug_frame(&debug_frame, sections, base_address) {
                    Ok(index) => ModuleUnwindDataInternal::DwarfCfiIndexAndDebugFrame(
                        index,
                        Arc::new(debug_frame),
                    ),
                    Err(_) => ModuleUnwindDataInternal::None,
                }
            }
            ModuleUnwindData::None => ModuleUnwindDataInternal::None,
        }
    }
}

pub struct TextByteData<D: Deref<Target = [u8]>> {
    bytes: D,
    address_range: Range<u64>,
}

impl<D: Deref<Target = [u8]>> TextByteData<D> {
    pub fn new(bytes: D, address_range: Range<u64>) -> Self {
        Self {
            bytes,
            address_range,
        }
    }

    pub fn get_bytes(&self, address_range: Range<u64>) -> Option<&[u8]> {
        let rel_start = address_range.start.checked_sub(self.address_range.start)?;
        let rel_start = usize::try_from(rel_start).ok()?;
        let rel_end = address_range.end.checked_sub(self.address_range.start)?;
        let rel_end = usize::try_from(rel_end).ok()?;
        self.bytes.get(rel_start..rel_end)
    }

    pub fn address_range(&self) -> Range<u64> {
        self.address_range.clone()
    }
}

pub struct Module<D: Deref<Target = [u8]>> {
    #[allow(unused)]
    name: String,
    address_range: Range<u64>,
    base_address: u64,
    sections: ModuleSectionAddressRanges,
    unwind_data: ModuleUnwindDataInternal<D>,
    text_data: Option<TextByteData<D>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSectionAddressRanges {
    pub text: Option<Range<u64>>,
    pub text_env: Option<Range<u64>>,
    pub stubs: Option<Range<u64>>,
    pub stub_helper: Option<Range<u64>>,
    pub eh_frame: Option<Range<u64>>,
    pub eh_frame_hdr: Option<Range<u64>>,
    pub got: Option<Range<u64>>,
}

impl<D: Deref<Target = [u8]>> Module<D> {
    pub fn new(
        name: String,
        address_range: std::ops::Range<u64>,
        base_address: u64,
        sections: ModuleSectionAddressRanges,
        unwind_data: ModuleUnwindData<D>,
        text_data: Option<TextByteData<D>>,
    ) -> Self {
        let unwind_data = ModuleUnwindDataInternal::new(unwind_data, &sections, base_address);
        Self {
            name,
            address_range,
            base_address,
            sections,
            unwind_data,
            text_data,
        }
    }
}
