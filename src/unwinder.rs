use gimli::{EndianReader, LittleEndian};

use super::arcdata::{ArcData, ArcDataReader};
use super::cache::Cache;
use super::error::{Error, UnwinderError};
use super::rule_cache::CacheResult;
use super::rules::{UnwindRule, UnwindRuleArm64};
use super::unwind_result::UnwindResult;
use super::unwinders::{CompactUnwindInfoUnwinder, DwarfUnwinderAarch64};
use super::unwindregs::UnwindRegsArm64;

use std::marker::PhantomData;
use std::ops::DerefMut;
use std::{
    fmt::Debug,
    ops::{Deref, Range},
    sync::Arc,
};

pub trait Arch {
    type UnwindRule: UnwindRule;
    type Regs;
}

struct ArchArm64;
impl Arch for ArchArm64 {
    type UnwindRule = UnwindRuleArm64;
    type Regs = UnwindRegsArm64;
}

pub struct Unwinder<D: Deref<Target = [u8]>, A: Arch> {
    /// sorted by address_range.start
    modules: Vec<Module<D>>,
    /// Incremented every time modules is changed.
    modules_generation: u16,
    _placeholder: PhantomData<A>,
}

impl<D: Deref<Target = [u8]>, A: Arch> Default for Unwinder<D, A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Deref<Target = [u8]>, A: Arch> Unwinder<D, A> {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            modules_generation: 0,
            _placeholder: PhantomData,
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

    pub fn unwind_first<F>(
        &self,
        pc: u64,
        regs: &mut UnwindRegsArm64,
        cache: &mut Cache<D, UnwindRuleArm64>,
        read_mem: &mut F,
    ) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        // eprintln!("unwind_first for {:x}", pc);

        let cache_handle =
            match cache
                .rule_cache
                .try_unwind(pc, self.modules_generation, regs, read_mem)
            {
                CacheResult::Hit(result) => return result,
                CacheResult::Miss(handle) => handle,
            };

        let unwind_rule = match self.unwind_first_impl(pc, regs, cache, read_mem) {
            Ok(UnwindResult::ExecRule(rule)) => rule,
            Ok(UnwindResult::Uncacheable(return_address)) => return Ok(return_address),
            Err(_) => UnwindRuleArm64::UseFramePointer,
        };
        cache.rule_cache.insert(cache_handle, unwind_rule);
        unwind_rule.exec(regs, read_mem)
    }

    fn unwind_first_impl<F>(
        &self,
        pc: u64,
        regs: &mut UnwindRegsArm64,
        cache: &mut Cache<D, UnwindRuleArm64>,
        read_mem: &mut F,
    ) -> Result<UnwindResult<UnwindRuleArm64>, UnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let module_index = self
            .find_module_for_address(pc)
            .ok_or(UnwinderError::NoModule)?;
        let module = &self.modules[module_index];
        let rel_pc = (pc - module.base_address) as u32;
        module.unwind_first(regs, pc, rel_pc, read_mem, cache)
    }

    pub fn unwind_next<F>(
        &self,
        return_address: u64,
        regs: &mut UnwindRegsArm64,
        cache: &mut Cache<D, UnwindRuleArm64>,
        read_mem: &mut F,
    ) -> Result<u64, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        // eprintln!("unwind_next for {:x}", return_address);
        let cache_handle = match cache.rule_cache.try_unwind(
            return_address - 1,
            self.modules_generation,
            regs,
            read_mem,
        ) {
            CacheResult::Hit(result) => return result,
            CacheResult::Miss(handle) => handle,
        };

        let unwind_rule = match self.unwind_next_impl(return_address, regs, cache, read_mem) {
            Ok(UnwindResult::ExecRule(rule)) => rule,
            Ok(UnwindResult::Uncacheable(return_address)) => return Ok(return_address),
            Err(_) => UnwindRuleArm64::UseFramePointer,
        };
        cache.rule_cache.insert(cache_handle, unwind_rule);
        unwind_rule.exec(regs, read_mem)
    }

    fn unwind_next_impl<F>(
        &self,
        return_address: u64,
        regs: &mut UnwindRegsArm64,
        cache: &mut Cache<D, UnwindRuleArm64>,
        read_mem: &mut F,
    ) -> Result<UnwindResult<UnwindRuleArm64>, UnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let module_index = self
            .find_module_for_address(return_address - 1)
            .ok_or(UnwinderError::NoModule)?;
        let module = &self.modules[module_index];
        let rel_ra = (return_address - module.base_address) as u32;
        module.unwind_next(regs, return_address, rel_ra, read_mem, cache)
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
}

pub enum UnwindData<D: Deref<Target = [u8]>> {
    CompactUnwindInfo(D),
    CompactUnwindInfoAndEhFrame(D, Arc<D>),
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

    fn unwind_first<F>(
        &self,
        regs: &mut UnwindRegsArm64,
        pc: u64,
        rel_pc: u32,
        read_mem: &mut F,
        cache: &mut Cache<D, UnwindRuleArm64>,
    ) -> Result<UnwindResult<UnwindRuleArm64>, UnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        // eprintln!(
        //     "Unwinding at pc {} + 0x{:x} (= 0x{:x}) with regs {:?}",
        //     self.name, rel_pc, pc, regs
        // );
        let unwind_result = match &self.unwind_data {
            UnwindData::CompactUnwindInfo(data) => {
                // eprintln!("unwinding with cui in module {}", self.name);
                let mut unwinder =
                    CompactUnwindInfoUnwinder::<ArcDataReader<D>>::new(&data[..], None);
                unwinder.unwind_first(regs, pc, rel_pc, read_mem)?
            }
            UnwindData::CompactUnwindInfoAndEhFrame(unwind_data, eh_frame_data) => {
                // eprintln!("unwinding with cui and eh_frame in module {}", self.name);
                let mut dwarf_unwinder = DwarfUnwinderAarch64::new(
                    EndianReader::new(ArcData(eh_frame_data.clone()), LittleEndian),
                    cache.eh_frame_unwind_context.deref_mut(),
                    &self.sections,
                );
                let mut unwinder =
                    CompactUnwindInfoUnwinder::new(&unwind_data[..], Some(&mut dwarf_unwinder));
                unwinder.unwind_first(regs, pc, rel_pc, read_mem)?
            }
            UnwindData::EhFrameHdrAndEhFrame(_, _) => {
                return Err(UnwinderError::UnhandledUnwindDataType)
            }
            UnwindData::EhFrame(_) => return Err(UnwinderError::UnhandledUnwindDataType),
            UnwindData::None => return Err(UnwinderError::NoUnwindData),
        };
        Ok(unwind_result)
    }

    fn unwind_next<F>(
        &self,
        regs: &mut UnwindRegsArm64,
        return_address: u64,
        rel_ra: u32,
        read_mem: &mut F,
        cache: &mut Cache<D, UnwindRuleArm64>,
    ) -> Result<UnwindResult<UnwindRuleArm64>, UnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        // eprintln!(
        //     "Unwinding at ra {} + 0x{:x} (= 0x{:x}) with regs {:?}",
        //     self.name, rel_ra, return_address, regs
        // );
        let unwind_result = match &self.unwind_data {
            UnwindData::CompactUnwindInfo(data) => {
                // eprintln!("unwinding with cui in module {}", self.name);
                let mut unwinder =
                    CompactUnwindInfoUnwinder::<ArcDataReader<D>>::new(&data[..], None);
                unwinder.unwind_next(regs, return_address, rel_ra, read_mem)?
            }
            UnwindData::CompactUnwindInfoAndEhFrame(unwind_data, eh_frame_data) => {
                // eprintln!("unwinding with cui and eh_frame in module {}", self.name);
                let mut dwarf_unwinder = DwarfUnwinderAarch64::new(
                    EndianReader::new(ArcData(eh_frame_data.clone()), LittleEndian),
                    &mut cache.eh_frame_unwind_context,
                    &self.sections,
                );
                let mut unwinder =
                    CompactUnwindInfoUnwinder::new(&unwind_data[..], Some(&mut dwarf_unwinder));
                unwinder.unwind_next(regs, return_address, rel_ra, read_mem)?
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

#[cfg(test)]
mod test {
    use std::io::Read;

    use super::*;

    #[test]
    fn test_basic() {
        let mut cache = Cache::new();
        let mut unwinder = Unwinder::<_, ArchArm64>::new();
        let mut unwind_info = Vec::new();
        let mut file = std::fs::File::open("fixtures/macos/arm64/fp/query-api.__unwind_info")
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
            UnwindData::CompactUnwindInfo(unwind_info),
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
        let mut regs = UnwindRegsArm64::new(0x1003fc000 + 0xe4830, 0x10, 0x20);
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
