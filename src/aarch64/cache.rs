use std::ops::Deref;

use super::unwind_rule::*;
use crate::cache::*;

/// The unwinder cache type for [`UnwinderAarch64`](super::UnwinderAarch64).
pub struct CacheAarch64<D: Deref<Target = [u8]>, P: AllocationPolicy<D> = MayAllocateDuringUnwind>(
    pub Cache<D, UnwindRuleAarch64, P>,
);

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> CacheAarch64<D, P> {
    /// Create a new cache.
    pub fn new() -> Self {
        Self(Cache::new())
    }

    /// Returns a snapshot of the cache usage statistics.
    pub fn stats(&self) -> CacheStats {
        self.0.rule_cache.stats()
    }
}

impl<D: Deref<Target = [u8]>, P: AllocationPolicy<D>> Default for CacheAarch64<D, P> {
    fn default() -> Self {
        Self::new()
    }
}
