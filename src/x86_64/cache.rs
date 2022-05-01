use std::ops::Deref;

use super::unwind_rule::*;
use crate::cache::*;

/// The unwinder cache type for [`UnwinderX86_64`](super::UnwinderX86_64).
pub struct CacheX86_64<D: Deref<Target = [u8]>, P: AllocationPolicy<D> = MayAllocateDuringUnwind>(
    pub Cache<D, UnwindRuleX86_64, P>,
);

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> CacheX86_64<D, P> {
    /// Create a new cache.
    pub fn new() -> Self {
        Self(Cache::new())
    }

    /// Returns a snapshot of the cache usage statistics.
    pub fn stats(&self) -> CacheStats {
        self.0.rule_cache.stats()
    }
}

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> Default for CacheX86_64<D, P> {
    fn default() -> Self {
        Self::new()
    }
}
