use std::ops::Deref;

use crate::{rule_cache::RuleCache, rules::UnwindRule};

use super::arcdata::ArcDataReader;

pub struct Cache<D: Deref<Target = [u8]>, R: UnwindRule> {
    pub(crate) eh_frame_unwind_context: Box<gimli::UnwindContext<ArcDataReader<D>>>,
    pub(crate) rule_cache: RuleCache<R>,
}

impl<D: Deref<Target = [u8]>, R: UnwindRule> Cache<D, R> {
    pub fn new() -> Self {
        Self {
            eh_frame_unwind_context: Box::new(gimli::UnwindContext::new()),
            rule_cache: RuleCache::new(),
        }
    }
}

impl<D: Deref<Target = [u8]>, R: UnwindRule> Default for Cache<D, R> {
    fn default() -> Self {
        Self::new()
    }
}
