use std::ops::Deref;

use super::unwind_rule::*;
use crate::cache::*;

pub struct CacheX86_64<D: Deref<Target = [u8]>, P: AllocationPolicy<D> = MayAllocateDuringUnwind>(
    pub Cache<D, UnwindRuleX86_64, P>,
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
