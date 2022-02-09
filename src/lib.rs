mod arcdata;
mod arch;
mod cache;
mod code_address;
mod display_utils;
mod error;
mod rule_cache;
mod rules;
mod unwind_result;
mod unwinder;
mod unwinders;
mod unwindregs;

use std::ops::Deref;

pub use code_address::CodeAddress;
pub use unwinder::{Module, SectionAddresses, UnwindData, Unwinder};
pub use unwindregs::*;

use arch::{ArchAarch64, ArchX86_64};
use cache::Cache;
use error::Error;
use rules::{UnwindRuleAarch64, UnwindRuleX86_64};
use unwinder::UnwinderInternal;

#[cfg(target_arch = "aarch64")]
pub type CacheNative<D> = CacheAarch64<D>;
#[cfg(target_arch = "aarch64")]
pub type UnwinderNative<D> = UnwinderAarch64<D>;

#[cfg(target_arch = "x86_64")]
pub type CacheNative<D> = CacheX86_64<D>;
#[cfg(target_arch = "x86_64")]
pub type UnwinderNative<D> = UnwinderX86_64<D>;

#[derive(Default)]
pub struct CacheAarch64<D: Deref<Target = [u8]>>(Cache<D, UnwindRuleAarch64>);

impl<D: Deref<Target = [u8]>> CacheAarch64<D> {
    pub fn new() -> Self {
        Self(Cache::new())
    }
}

#[derive(Default)]
pub struct UnwinderAarch64<D: Deref<Target = [u8]>>(UnwinderInternal<D, ArchAarch64>);

impl<D: Deref<Target = [u8]>> UnwinderAarch64<D> {
    pub fn new() -> Self {
        Self(UnwinderInternal::new())
    }
}

impl<D: Deref<Target = [u8]>> Unwinder for UnwinderAarch64<D> {
    type UnwindRegs = UnwindRegsAarch64;
    type Cache = CacheAarch64<D>;
    type Module = Module<D>;

    fn add_module(&mut self, module: Module<D>) {
        self.0.add_module(module);
    }

    fn remove_module(&mut self, module_address_range_start: u64) {
        self.0.remove_module(module_address_range_start);
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
        self.0.unwind_first(pc, regs, &mut cache.0, read_mem)
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
        self.0
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
pub struct UnwinderX86_64<D: Deref<Target = [u8]>>(UnwinderInternal<D, ArchX86_64>);

impl<D: Deref<Target = [u8]>> UnwinderX86_64<D> {
    pub fn new() -> Self {
        Self(UnwinderInternal::new())
    }
}

impl<D: Deref<Target = [u8]>> Unwinder for UnwinderX86_64<D> {
    type UnwindRegs = UnwindRegsX86_64;
    type Cache = CacheX86_64<D>;
    type Module = Module<D>;

    fn add_module(&mut self, module: Module<D>) {
        self.0.add_module(module);
    }

    fn remove_module(&mut self, module_address_range_start: u64) {
        self.0.remove_module(module_address_range_start);
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
        self.0.unwind_first(pc, regs, &mut cache.0, read_mem)
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
        self.0
            .unwind_next(return_address, regs, &mut cache.0, read_mem)
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
