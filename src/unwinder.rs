use gimli::{EndianReader, LittleEndian};

use crate::arcdata::ArcData;
use crate::arch::{Arch, ArchAarch64, ArchX86_64};
use crate::cache::Cache;
use crate::error::{Error, UnwinderError};
use crate::rule_cache::CacheResult;
use crate::rules::{UnwindRule, UnwindRuleAarch64, UnwindRuleX86_64};
use crate::unwind_result::UnwindResult;
use crate::unwinders::{
    CompactUnwindInfoUnwinder, CompactUnwindInfoUnwinding, CuiUnwindResult, DwarfUnwinder,
    DwarfUnwinding,
};
use crate::unwindregs::{UnwindRegsAarch64, UnwindRegsX86_64};

use std::marker::PhantomData;
use std::{
    fmt::Debug,
    ops::{Deref, Range},
    sync::Arc,
};

#[cfg(target_arch = "aarch64")]
pub type CacheNative<D> = CacheAarch64<D>;
#[cfg(target_arch = "aarch64")]
pub type UnwinderNative<D> = UnwinderAarch64<D>;

#[cfg(target_arch = "x86_64")]
pub type CacheNative<D> = CacheX86_64<D>;
#[cfg(target_arch = "x86_64")]
pub type UnwinderNative<D> = UnwinderX86_64<D>;

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
    ) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>;

    fn unwind_next<F>(
        &self,
        return_address: u64,
        regs: &mut Self::UnwindRegs,
        cache: &mut Self::Cache,
        read_mem: &mut F,
    ) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>;
}

#[derive(Default)]
pub struct CacheAarch64<D: Deref<Target = [u8]>>(Cache<D, UnwindRuleAarch64>);

impl<D: Deref<Target = [u8]>> CacheAarch64<D> {
    pub fn new() -> Self {
        Self(Cache::new())
    }
}

#[derive(Default)]
pub struct UnwinderAarch64<D: Deref<Target = [u8]>> {
    internal: UnwinderInternal<D, ArchAarch64>,
}

impl<D: Deref<Target = [u8]>> UnwinderAarch64<D> {
    pub fn new() -> Self {
        Self {
            internal: UnwinderInternal::new(),
        }
    }
}

impl<D: Deref<Target = [u8]>> Unwinder for UnwinderAarch64<D> {
    type UnwindRegs = UnwindRegsAarch64;
    type Cache = CacheAarch64<D>;
    type Module = Module<D>;

    fn add_module(&mut self, module: Module<D>) {
        self.internal.add_module(module);
    }

    fn remove_module(&mut self, module_address_range_start: u64) {
        self.internal.remove_module(module_address_range_start);
    }

    fn unwind_first<F>(
        &self,
        pc: u64,
        regs: &mut UnwindRegsAarch64,
        cache: &mut CacheAarch64<D>,
        read_mem: &mut F,
    ) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        self.internal.unwind_first(pc, regs, &mut cache.0, read_mem)
    }

    fn unwind_next<F>(
        &self,
        return_address: u64,
        regs: &mut UnwindRegsAarch64,
        cache: &mut CacheAarch64<D>,
        read_mem: &mut F,
    ) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        self.internal
            .unwind_next(return_address, regs, &mut cache.0, read_mem)
    }
}

#[derive(Default)]
pub struct CacheX86_64<D: Deref<Target = [u8]>>(Cache<D, UnwindRuleX86_64>);

impl<D: Deref<Target = [u8]>> CacheX86_64<D> {
    pub fn new() -> Self {
        Self(Cache::new())
    }
}

#[derive(Default)]
pub struct UnwinderX86_64<D: Deref<Target = [u8]>> {
    internal: UnwinderInternal<D, ArchX86_64>,
}

impl<D: Deref<Target = [u8]>> UnwinderX86_64<D> {
    pub fn new() -> Self {
        Self {
            internal: UnwinderInternal::new(),
        }
    }
}

impl<D: Deref<Target = [u8]>> Unwinder for UnwinderX86_64<D> {
    type UnwindRegs = UnwindRegsX86_64;
    type Cache = CacheX86_64<D>;
    type Module = Module<D>;

    fn add_module(&mut self, module: Module<D>) {
        self.internal.add_module(module);
    }

    fn remove_module(&mut self, module_address_range_start: u64) {
        self.internal.remove_module(module_address_range_start);
    }

    fn unwind_first<F>(
        &self,
        pc: u64,
        regs: &mut UnwindRegsX86_64,
        cache: &mut CacheX86_64<D>,
        read_mem: &mut F,
    ) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        self.internal.unwind_first(pc, regs, &mut cache.0, read_mem)
    }

    fn unwind_next<F>(
        &self,
        return_address: u64,
        regs: &mut UnwindRegsX86_64,
        cache: &mut CacheX86_64<D>,
        read_mem: &mut F,
    ) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        self.internal
            .unwind_next(return_address, regs, &mut cache.0, read_mem)
    }
}

struct UnwinderInternal<
    D: Deref<Target = [u8]>,
    A: Arch + DwarfUnwinding + CompactUnwindInfoUnwinding,
> {
    /// sorted by address_range.start
    modules: Vec<Module<D>>,
    /// Incremented every time modules is changed.
    modules_generation: u16,
    _arch: PhantomData<A>,
}

impl<D: Deref<Target = [u8]>, A: Arch + DwarfUnwinding + CompactUnwindInfoUnwinding> Default
    for UnwinderInternal<D, A>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Deref<Target = [u8]>, A: Arch + DwarfUnwinding + CompactUnwindInfoUnwinding>
    UnwinderInternal<D, A>
{
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            modules_generation: 0,
            _arch: PhantomData,
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
        address: u64,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule>,
        read_mem: &mut F,
        callback: G,
    ) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        G: FnOnce(
            &Module<D>,
            &mut A::UnwindRegs,
            &mut Cache<D, A::UnwindRule>,
            &mut F,
        ) -> Result<UnwindResult<A::UnwindRule>, UnwinderError>,
    {
        let cache_handle =
            match cache
                .rule_cache
                .try_unwind(address, self.modules_generation, regs, read_mem)
            {
                CacheResult::Hit(result) => return result,
                CacheResult::Miss(handle) => handle,
            };

        let module_index = self
            .find_module_for_address(address)
            .ok_or(Error::UnwindingFailed)?;
        let module = &self.modules[module_index];
        let unwind_rule = match callback(module, regs, cache, read_mem) {
            Ok(UnwindResult::ExecRule(rule)) => rule,
            Ok(UnwindResult::Uncacheable(return_address)) => return Ok(return_address),
            Err(_) => A::UnwindRule::fallback_rule(),
        };
        cache.rule_cache.insert(cache_handle, unwind_rule);
        unwind_rule.exec(regs, read_mem)
    }

    pub fn unwind_first<F>(
        &self,
        pc: u64,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule>,
        read_mem: &mut F,
    ) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        // eprintln!("unwind_first for {:x}", pc);
        self.with_cache(
            pc,
            regs,
            cache,
            read_mem,
            |module, regs, cache, read_mem| {
                Self::unwind_first_impl(module, pc, regs, cache, read_mem)
            },
        )
    }

    pub fn unwind_next<F>(
        &self,
        return_address: u64,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule>,
        read_mem: &mut F,
    ) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        // eprintln!("unwind_next for {:x}", return_address);
        self.with_cache(
            return_address - 1,
            regs,
            cache,
            read_mem,
            |module, regs, cache, read_mem| {
                Self::unwind_next_impl(module, return_address, regs, cache, read_mem)
            },
        )
    }

    fn unwind_first_impl<F>(
        module: &Module<D>,
        pc: u64,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule>,
        read_mem: &mut F,
    ) -> Result<UnwindResult<A::UnwindRule>, UnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let rel_pc = (pc - module.base_address) as u32;

        let unwind_result = match &module.unwind_data {
            UnwindData::CompactUnwindInfoAndEhFrame(unwind_data, eh_frame_data) => {
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
                        let mut dwarf_unwinder = DwarfUnwinder::<_, A>::new(
                            EndianReader::new(eh_frame_data, LittleEndian),
                            &mut cache.eh_frame_unwind_context,
                            &module.sections,
                        );
                        dwarf_unwinder.unwind_first_with_fde(regs, pc, fde_offset, read_mem)?
                    }
                    CuiUnwindResult::Err(err) => return Err(err.into()),
                }
            }
            UnwindData::EhFrameHdrAndEhFrame(_, _) => {
                return Err(UnwinderError::UnhandledUnwindDataType)
            }
            UnwindData::EhFrame(_) => return Err(UnwinderError::UnhandledUnwindDataType),
            UnwindData::None => return Err(UnwinderError::NoUnwindData),
        };
        Ok(unwind_result)
    }

    fn unwind_next_impl<F>(
        module: &Module<D>,
        return_address: u64,
        regs: &mut A::UnwindRegs,
        cache: &mut Cache<D, A::UnwindRule>,
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
            UnwindData::CompactUnwindInfoAndEhFrame(unwind_data, eh_frame_data) => {
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
                        let mut dwarf_unwinder = DwarfUnwinder::<_, A>::new(
                            EndianReader::new(eh_frame_data, LittleEndian),
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
            UnwindData::EhFrameHdrAndEhFrame(_, _) => {
                return Err(UnwinderError::UnhandledUnwindDataType)
            }
            UnwindData::EhFrame(_) => return Err(UnwinderError::UnhandledUnwindDataType),
            UnwindData::None => return Err(UnwinderError::NoUnwindData),
        };
        Ok(unwind_result)
    }
}

pub enum UnwindData<D: Deref<Target = [u8]>> {
    CompactUnwindInfoAndEhFrame(D, Option<Arc<D>>),
    EhFrameHdrAndEhFrame(D, Arc<D>),
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
    sections: SectionAddresses,
    unwind_data: UnwindData<D>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionAddresses {
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
        sections: SectionAddresses,
        unwind_data: UnwindData<D>,
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

#[cfg(test)]
mod test {
    use std::io::Read;

    use super::*;

    #[test]
    fn test_basic() {
        let mut cache = CacheAarch64::default();
        let mut unwinder = UnwinderAarch64::new();
        let mut unwind_info = Vec::new();
        let mut file = std::fs::File::open("fixtures/macos/aarch64/fp/query-api.__unwind_info")
            .expect("file opening failed");
        file.read_to_end(&mut unwind_info)
            .expect("file reading failed");
        unwinder.add_module(Module::new(
            "query-api".to_string(),
            0x1003fc000..0x100634000,
            0x1003fc000,
            0x100000000,
            SectionAddresses {
                text: 0,
                eh_frame: 0,
                eh_frame_hdr: 0,
                got: 0,
            },
            UnwindData::CompactUnwindInfoAndEhFrame(unwind_info, None),
        ));
        let stack = [
            1,
            2,
            3,
            4,
            0x40,
            0x1003fc000 + 0x100dc4,
            5,
            6,
            0x70,
            0x1003fc000 + 0x12ca28,
            7,
            8,
            9,
            10,
            0x0,
            0x0,
        ];
        let mut read_mem = |addr| Ok(stack[(addr / 8) as usize]);
        let mut regs = UnwindRegsAarch64::new(0x1003fc000 + 0xe4830, 0x10, 0x20);
        // There's a frameless function at e0d2c.
        let res =
            unwinder.unwind_first(0x1003fc000 + 0x1292c0, &mut regs, &mut cache, &mut read_mem);
        assert_eq!(res, Ok(0x1003fc000 + 0xe4830));
        assert_eq!(regs.sp(), 0x10);
        let res = unwinder.unwind_next(0x1003fc000 + 0xe4830, &mut regs, &mut cache, &mut read_mem);
        assert_eq!(res, Ok(0x1003fc000 + 0x100dc4));
        assert_eq!(regs.sp(), 0x30);
        assert_eq!(regs.fp(), 0x40);
        let res =
            unwinder.unwind_next(0x1003fc000 + 0x100dc4, &mut regs, &mut cache, &mut read_mem);
        assert_eq!(res, Ok(0x1003fc000 + 0x12ca28));
        assert_eq!(regs.sp(), 0x50);
        assert_eq!(regs.fp(), 0x70);
        let res =
            unwinder.unwind_next(0x1003fc000 + 0x100dc4, &mut regs, &mut cache, &mut read_mem);
        assert_eq!(res, Err(Error::StackEndReached));
    }
}
