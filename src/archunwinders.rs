use std::ops::Deref;

use crate::arch::{ArchAarch64, ArchX86_64};
use crate::cache::Cache;
use crate::error::Error;
use crate::rules::{UnwindRuleAarch64, UnwindRuleX86_64};
use crate::unwinder::UnwinderInternal;
use crate::unwinder::{Module, Unwinder};
use crate::unwindregs::*;

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
    ) -> Result<Option<u64>, Error>
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
    ) -> Result<Option<u64>, Error>
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
    ) -> Result<Option<u64>, Error>
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
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        self.0
            .unwind_next(return_address, regs, &mut cache.0, read_mem)
    }
}
