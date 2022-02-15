use std::ops::Deref;

use crate::arch::{ArchAarch64, ArchX86_64};
use crate::cache::{AllocationPolicy, Cache, MayAllocateDuringUnwind};
use crate::error::Error;
use crate::rules::{UnwindRuleAarch64, UnwindRuleX86_64};
use crate::unwinder::UnwinderInternal;
use crate::unwinder::{Module, Unwinder};
use crate::unwindregs::*;

pub struct CacheAarch64<D: Deref<Target = [u8]>, P: AllocationPolicy<D> = MayAllocateDuringUnwind>(
    Cache<D, UnwindRuleAarch64, P>,
);

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> CacheAarch64<D, P> {
    pub fn new() -> Self {
        Self(Cache::new())
    }
}

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> Default for CacheAarch64<D, P> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct UnwinderAarch64<
    D: Deref<Target = [u8]>,
    P: AllocationPolicy<D> = MayAllocateDuringUnwind,
>(UnwinderInternal<D, ArchAarch64, P>);

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> Default for UnwinderAarch64<D, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> UnwinderAarch64<D, P> {
    pub fn new() -> Self {
        Self(UnwinderInternal::new())
    }
}

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> Unwinder for UnwinderAarch64<D, P> {
    type UnwindRegs = UnwindRegsAarch64;
    type Cache = CacheAarch64<D, P>;
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
        cache: &mut CacheAarch64<D, P>,
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
        cache: &mut CacheAarch64<D, P>,
        read_mem: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        self.0
            .unwind_next(return_address, regs, &mut cache.0, read_mem)
    }
}

pub struct CacheX86_64<D: Deref<Target = [u8]>, P: AllocationPolicy<D> = MayAllocateDuringUnwind>(
    Cache<D, UnwindRuleX86_64, P>,
);

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> CacheX86_64<D, P> {
    pub fn new() -> Self {
        Self(Cache::new())
    }
}

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> Default for CacheX86_64<D, P> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct UnwinderX86_64<D: Deref<Target = [u8]>, P: AllocationPolicy<D> = MayAllocateDuringUnwind>(
    UnwinderInternal<D, ArchX86_64, P>,
);

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> Default for UnwinderX86_64<D, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> UnwinderX86_64<D, P> {
    pub fn new() -> Self {
        Self(UnwinderInternal::new())
    }
}

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> Unwinder for UnwinderX86_64<D, P> {
    type UnwindRegs = UnwindRegsX86_64;
    type Cache = CacheX86_64<D, P>;
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
        cache: &mut CacheX86_64<D, P>,
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
        cache: &mut CacheX86_64<D, P>,
        read_mem: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        self.0
            .unwind_next(return_address, regs, &mut cache.0, read_mem)
    }
}
