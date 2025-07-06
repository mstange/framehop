use super::unwind_rule::*;
use crate::cache::*;

/// The unwinder cache type for [`UnwinderArmhf`](super::UnwinderArmhf).
pub struct CacheArmhf<P: AllocationPolicy = MayAllocateDuringUnwind>(pub Cache<UnwindRuleArmhf, P>);

impl CacheArmhf<MayAllocateDuringUnwind> {
    /// Create a new cache.
    pub fn new() -> Self {
        Self(Cache::new())
    }
}

impl<P: AllocationPolicy> CacheArmhf<P> {
    /// Create a new cache.
    pub fn new_in() -> Self {
        Self(Cache::new())
    }

    /// Returns a snapshot of the cache usage statistics.
    pub fn stats(&self) -> CacheStats {
        self.0.rule_cache.stats()
    }
}

impl<P: AllocationPolicy> Default for CacheArmhf<P> {
    fn default() -> Self {
        Self::new_in()
    }
}
