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

/// Unwinder is the trait that each CPU architecture's concrete unwinder type implements.
/// This trait's methods are what let you do the actual unwinding.
pub trait Unwinder {
    /// The unwind registers type for the targeted CPU architecture.
    type UnwindRegs;

    /// The unwind cache for the targeted CPU architecture.
    /// This is an associated type because the cache stores unwind rules, whose concrete
    /// type depends on the CPU arch, and because the cache can support different allocation
    /// policies.
    type Cache;

    /// The module type. This is an associated type because the concrete type varies
    /// depending on the type you use to give the module access to the unwind section data.
    type Module;

    /// Add a module that's loaded in the profiled process. This is how you provide unwind
    /// information and address ranges.
    ///
    /// This should be called whenever a new module is loaded into the process.
    fn add_module(&mut self, module: Self::Module);

    /// Remove a module that was added before using `add_module`, keyed by the start
    /// address of that module's address range. If no match is found, the call is ignored.
    /// This should be called whenever a module is unloaded from the process.
    fn remove_module(&mut self, module_avma_range_start: u64);

    /// Returns the highest code address that is known in this process based on the module
    /// address ranges. Returns 0 if no modules have been added.
    ///
    /// This method can be used together with
    /// [`PtrAuthMask::from_max_known_address`](crate::aarch64::PtrAuthMask::from_max_known_address)
    /// to make an educated guess at a pointer authentication mask for Aarch64 return addresses.
    fn max_known_code_address(&self) -> u64;

    /// Unwind a single frame, to recover return address and caller register values.
    /// This is the main entry point for unwinding.
    fn unwind_frame<F>(
        &self,
        address: FrameAddress,
        regs: &mut Self::UnwindRegs,
        cache: &mut Self::Cache,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>;

    /// Return an iterator that unwinds frame by frame until the end of the stack is found.
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

/// An iterator for unwinding the entire stack, starting from the initial register values.
///
/// The first yielded frame is the instruction pointer. Subsequent addresses are return
/// addresses.
///
/// This iterator attempts to detect if stack unwinding completed successfully, or if the
/// stack was truncated prematurely. If it thinks that it successfully found the root
/// function, it will complete with `Ok(None)`, otherwise it will complete with `Err(...)`.
/// However, the detection does not work in all cases, so you should expect `Err(...)` to
/// be returned even during normal operation. As a result, it is not recommended to use
/// this iterator as a `FallibleIterator`, because you might lose the entire stack if the
/// last iteration returns `Err(...)`.
///
/// Lifetimes:
///
///  - `'u`: The lifetime of the [`Unwinder`].
///  - `'c`: The lifetime of the unwinder cache.
///  - `'r`: The lifetime of the exclusive access to the `read_stack` callback.
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
    /// Create a new iterator. You'd usually use [`Unwinder::iter_frames`] instead.
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
    /// Yield the next frame in the stack.
    ///
    /// The first frame is `Ok(Some(FrameAddress::InstructionPointer(...)))`.
    /// Subsequent frames are `Ok(Some(FrameAddress::ReturnAddress(...)))`.
    ///
    /// If a root function has been reached, this iterator completes with `Ok(None)`.
    /// Otherwise it completes with `Err(...)`, usually indicating that a certain stack
    /// address could not be read.
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
    /// sorted by avma_range.start
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
            .binary_search_by_key(&module.avma_range.start, |module| module.avma_range.start)
        {
            Ok(i) => {
                eprintln!(
                    "Now we have two modules at the same start address 0x{:x}. This can't be good.",
                    module.avma_range.start
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
                module.avma_range.start
            })
        {
            self.modules.remove(index);
            self.modules_generation = next_global_modules_generation();
        };
    }

    pub fn max_known_code_address(&self) -> u64 {
        self.modules.last().map_or(0, |m| m.avma_range.end)
    }

    fn find_module_for_address(&self, address: u64) -> Option<(usize, u32)> {
        let (module_index, module) = match self
            .modules
            .binary_search_by_key(&address, |m| m.avma_range.start)
        {
            Ok(i) => (i, &self.modules[i]),
            Err(insertion_index) => {
                if insertion_index == 0 {
                    // address is before first known module
                    return None;
                }
                let i = insertion_index - 1;
                let module = &self.modules[i];
                if module.avma_range.end <= address {
                    // address is after this module
                    return None;
                }
                (i, module)
            }
        };
        if address < module.base_avma {
            // Invalid base address
            return None;
        }
        let relative_address = u32::try_from(address - module.base_avma).ok()?;
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
        let is_first_frame = !address.is_return_address();
        let unwind_result = match &module.unwind_data {
            ModuleUnwindDataInternal::CompactUnwindInfoAndEhFrame(unwind_data, eh_frame_data) => {
                // eprintln!("unwinding with cui and eh_frame in module {}", module.name);
                let text_bytes = module.text_data.as_ref().and_then(|data| {
                    let offset_from_base =
                        u32::try_from(data.avma_range.start.checked_sub(module.base_avma)?).ok()?;
                    Some(TextBytes::new(offset_from_base, &data.bytes[..]))
                });
                let stubs_range = if let Some(stubs_range) = &module.svma_info.stubs {
                    (
                        (stubs_range.start - module.svma_info.base_svma) as u32,
                        (stubs_range.end - module.svma_info.base_svma) as u32,
                    )
                } else {
                    (0, 0)
                };
                let stub_helper_range =
                    if let Some(stub_helper_range) = &module.svma_info.stub_helper {
                        (
                            (stub_helper_range.start - module.svma_info.base_svma) as u32,
                            (stub_helper_range.end - module.svma_info.base_svma) as u32,
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
                            &mut cache.gimli_unwind_context,
                            &module.svma_info,
                        );
                        dwarf_unwinder.unwind_frame_with_fde(
                            regs,
                            is_first_frame,
                            rel_lookup_address,
                            fde_offset,
                            read_stack,
                        )?
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
                    &mut cache.gimli_unwind_context,
                    &module.svma_info,
                );
                let fde_offset = dwarf_unwinder
                    .get_fde_offset_for_relative_address(rel_lookup_address)
                    .ok_or(UnwinderError::EhFrameHdrCouldNotFindAddress)?;
                dwarf_unwinder.unwind_frame_with_fde(
                    regs,
                    is_first_frame,
                    rel_lookup_address,
                    fde_offset,
                    read_stack,
                )?
            }
            ModuleUnwindDataInternal::DwarfCfiIndexAndEhFrame(index, eh_frame_data) => {
                let eh_frame_data = ArcData(eh_frame_data.clone());
                let mut dwarf_unwinder = DwarfUnwinder::<_, A, P::GimliStorage>::new(
                    EndianReader::new(eh_frame_data, LittleEndian),
                    UnwindSectionType::EhFrame,
                    None,
                    &mut cache.gimli_unwind_context,
                    &module.svma_info,
                );
                let fde_offset = index
                    .fde_offset_for_relative_address(rel_lookup_address)
                    .ok_or(UnwinderError::DwarfCfiIndexCouldNotFindAddress)?;
                dwarf_unwinder.unwind_frame_with_fde(
                    regs,
                    is_first_frame,
                    rel_lookup_address,
                    fde_offset,
                    read_stack,
                )?
            }
            ModuleUnwindDataInternal::DwarfCfiIndexAndDebugFrame(index, debug_frame_data) => {
                let debug_frame_data = ArcData(debug_frame_data.clone());
                let mut dwarf_unwinder = DwarfUnwinder::<_, A, P::GimliStorage>::new(
                    EndianReader::new(debug_frame_data, LittleEndian),
                    UnwindSectionType::DebugFrame,
                    None,
                    &mut cache.gimli_unwind_context,
                    &module.svma_info,
                );
                let fde_offset = index
                    .fde_offset_for_relative_address(rel_lookup_address)
                    .ok_or(UnwinderError::DwarfCfiIndexCouldNotFindAddress)?;
                dwarf_unwinder.unwind_frame_with_fde(
                    regs,
                    is_first_frame,
                    rel_lookup_address,
                    fde_offset,
                    read_stack,
                )?
            }
            ModuleUnwindDataInternal::None => return Err(UnwinderError::NoModuleUnwindData),
        };
        Ok(unwind_result)
    }
}

/// The unwind data that should be used when unwinding addresses inside this module.
/// Unwind data describes how to recover register values of the caller frame.
///
/// The type of unwind information you use depends on the platform and what's available
/// in the binary.
pub enum ModuleUnwindData<D: Deref<Target = [u8]>> {
    /// Used on macOS, with mach-O binaries. Compact unwind info is in the `__unwind_info`
    /// section and is sometimes supplemented with DWARF CFI information in the `__eh_frame`
    /// section.
    CompactUnwindInfoAndEhFrame(D, Option<D>),
    /// Used with ELF binaries (Linux and friends), in the `.eh_frame_hdr` and `.eh_frame`
    /// sections. Contains an index and DWARF CFI.
    EhFrameHdrAndEhFrame(D, D),
    /// Used with ELF binaries (Linux and friends), in the `.eh_frame` section. Contains
    /// DWARF CFI. We create a binary index for the FDEs when a module with this unwind
    /// data type is added.
    EhFrame(D),
    /// Used with ELF binaries (Linux and friends), in the `.debug_frame` section. Contains
    /// DWARF CFI. We create a binary index for the FDEs when a module with this unwind
    /// data type is added.
    DebugFrame(D),
    /// No unwind information is used. Unwinding in this module will use a fallback rule
    /// (usually frame pointer unwinding).
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
    fn new(unwind_data: ModuleUnwindData<D>, svma_info: &ModuleSvmaInfo) -> Self {
        match unwind_data {
            ModuleUnwindData::CompactUnwindInfoAndEhFrame(cui, eh_frame) => {
                ModuleUnwindDataInternal::CompactUnwindInfoAndEhFrame(cui, eh_frame.map(Arc::new))
            }
            ModuleUnwindData::EhFrameHdrAndEhFrame(eh_frame_hdr, eh_frame) => {
                ModuleUnwindDataInternal::EhFrameHdrAndEhFrame(eh_frame_hdr, Arc::new(eh_frame))
            }
            ModuleUnwindData::EhFrame(eh_frame) => {
                match DwarfCfiIndex::try_new_eh_frame(&eh_frame, svma_info) {
                    Ok(index) => {
                        ModuleUnwindDataInternal::DwarfCfiIndexAndEhFrame(index, Arc::new(eh_frame))
                    }
                    Err(_) => ModuleUnwindDataInternal::None,
                }
            }
            ModuleUnwindData::DebugFrame(debug_frame) => {
                match DwarfCfiIndex::try_new_debug_frame(&debug_frame, svma_info) {
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

/// Used to supply raw instruction bytes to the unwinder, which uses it to analyze
/// instructions in order to provide high quality unwinding inside function prologues and
/// epilogues.
///
/// This is only needed on macOS, because mach-O `__unwind_info` and `__eh_frame` only
/// cares about accuracy in function bodies, not in function prologues and epilogues.
///
/// On Linux, compilers produce `.eh_frame` and `.debug_frame` which provides correct
/// unwind information for all instructions including those in function prologues and
/// epilogues, so instruction analysis is not needed.
pub struct TextByteData<D: Deref<Target = [u8]>> {
    bytes: D,
    avma_range: Range<u64>,
}

impl<D: Deref<Target = [u8]>> TextByteData<D> {
    /// Supply the bytes which cover `avma_range` in the process virtual memory.
    /// Both arguments should have the same length.
    pub fn new(bytes: D, avma_range: Range<u64>) -> Self {
        Self { bytes, avma_range }
    }

    /// Return a byte slice for the requested range, if in-bounds.
    pub fn get_bytes(&self, avma_range: Range<u64>) -> Option<&[u8]> {
        let rel_start = avma_range.start.checked_sub(self.avma_range.start)?;
        let rel_start = usize::try_from(rel_start).ok()?;
        let rel_end = avma_range.end.checked_sub(self.avma_range.start)?;
        let rel_end = usize::try_from(rel_end).ok()?;
        self.bytes.get(rel_start..rel_end)
    }

    /// The address range covered by the supplied bytes, in process virtual memory.
    /// "Actual virtual memory address range"
    pub fn avma_range(&self) -> Range<u64> {
        self.avma_range.clone()
    }
}

/// Information about a module that is loaded in a process. You might know this under a
/// different name, for example: (Shared) library, binary image, DSO ("Dynamic shared object")
///
/// The unwinder needs to have an up-to-date list of modules so that it can match an
/// absolute address to the right module, and so that it can find that module's unwind
/// information.
pub struct Module<D: Deref<Target = [u8]>> {
    /// The name or file path of the module. Unused, it's just there for easier debugging.
    #[allow(unused)]
    name: String,
    /// The address range where this module is mapped into the process.
    avma_range: Range<u64>,
    /// The base address of this module, in the process's address space. On Linux, the base
    /// address can sometimes be different from the start address of the mapped range.
    base_avma: u64,
    /// Information about various addresses in the module.
    svma_info: ModuleSvmaInfo,
    /// The unwind data that should be used for unwinding addresses from this module.
    unwind_data: ModuleUnwindDataInternal<D>,
    /// The raw assembly bytes of this module. Used for instruction analysis to ensure
    /// correct unwinding inside function prologues and epilogues.
    text_data: Option<TextByteData<D>>,
}

/// The addresses of various sections in the module.
///
/// These are SVMAs, "stated virtual memory addresses", i.e. addresses as stated
/// in the object, as opposed to AVMAs, "actual virtual memory addresses", i.e. addresses
/// in the virtual memory of the profiled process.
///
/// Code addresses inside a module's unwind information are usually written down as SVMAs,
/// or as relative addresses. For example, DWARF CFI can have code addresses expressed as
/// relative-to-.text addresses or as absolute SVMAs. And mach-O compact unwind info
/// contains addresses relative to the image base address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSvmaInfo {
    /// The image base address, as stated in the object. For mach-O objects, this is the
    /// vmaddr of the `__TEXT` segment. For ELF objects, this is zero.
    ///
    /// This is used to convert between SVMAs and relative addresses.
    pub base_svma: u64,
    /// The address range of the `__text` or `.text` section. This is where most of the
    /// compiled code is stored.
    ///
    /// This is used to detect whether we need to do instruction analysis for an address.
    pub text: Option<Range<u64>>,
    /// The address range of the `text_env` section, if present. If present, this contains
    /// functions which have been marked as "cold". It stores executable code, just like
    /// the text section.
    ///
    /// This is used to detect whether we need to do instruction analysis for an address.
    pub text_env: Option<Range<u64>>,
    /// The address range of the mach-O `__stubs` section. Contains small pieces of
    /// executable code for calling imported functions. Code inside this section is not
    /// covered by the unwind information in `__unwind_info`.
    ///
    /// This is used to exclude addresses in this section from incorrectly applying
    /// `__unwind_info` opcodes. It is also used to infer unwind rules for the known
    /// structure of stub functions.
    pub stubs: Option<Range<u64>>,
    /// The address range of the mach-O `__stub_helper` section. Contains small pieces of
    /// executable code for calling imported functions. Code inside this section is not
    /// covered by the unwind information in `__unwind_info`.
    ///
    /// This is used to exclude addresses in this section from incorrectly applying
    /// `__unwind_info` opcodes. It is also used to infer unwind rules for the known
    /// structure of stub helper
    /// functions.
    pub stub_helper: Option<Range<u64>>,
    /// The address range of the `__eh_frame` or `.eh_frame` section. This is used during
    /// DWARF CFI processing, to resolve eh_frame-relative addresses.
    pub eh_frame: Option<Range<u64>>,
    /// The address range of the `.eh_frame_hdr` section. This is used during
    /// DWARF CFI processing, to resolve eh_frame_hdr-relative addresses.
    pub eh_frame_hdr: Option<Range<u64>>,
    /// The address range of the `.got` section (Global Offset Table). This is used
    /// during DWARF CFI processing, to resolve got-relative addresses.
    pub got: Option<Range<u64>>,
}

impl<D: Deref<Target = [u8]>> Module<D> {
    pub fn new(
        name: String,
        avma_range: std::ops::Range<u64>,
        base_avma: u64,
        svma_info: ModuleSvmaInfo,
        unwind_data: ModuleUnwindData<D>,
        text_data: Option<TextByteData<D>>,
    ) -> Self {
        let unwind_data = ModuleUnwindDataInternal::new(unwind_data, &svma_info);
        Self {
            name,
            avma_range,
            base_avma,
            svma_info,
            unwind_data,
            text_data,
        }
    }
}
