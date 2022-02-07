use std::ops::Deref;

use crate::rule_cache::RuleCache;

use super::arcdata::ArcDataReader;

pub struct Cache<D: Deref<Target = [u8]>> {
    pub(crate) eh_frame_unwind_context: Box<gimli::UnwindContext<ArcDataReader<D>>>,
    pub(crate) rule_cache: RuleCache,
}

impl<D: Deref<Target = [u8]>> Cache<D> {
    pub fn new() -> Self {
        Self {
            eh_frame_unwind_context: Box::new(gimli::UnwindContext::new()),
            rule_cache: RuleCache::new(),
        }
    }
}

impl<D: Deref<Target = [u8]>> Default for Cache<D> {
    fn default() -> Self {
        Self::new()
    }
}
