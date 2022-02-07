use crate::{error::Error, rules::UnwindRuleArm64, UnwindRegsArm64};

pub struct RuleCache {
    entries: Box<[Option<CacheEntry>; 509]>,
}

impl RuleCache {
    pub fn new() -> Self {
        Self {
            entries: Box::new([None; 509]),
        }
    }

    pub fn try_unwind<F>(
        &mut self,
        address: u64,
        modules_generation: u16,
        regs: &mut UnwindRegsArm64,
        read_mem: &mut F,
    ) -> CacheResult
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let slot = (address % 509) as u16;
        if let Some(entry) = &self.entries[slot as usize] {
            if entry.modules_generation == modules_generation && entry.address == address {
                return CacheResult::Hit(entry.unwind_rule.exec(regs, read_mem));
            }
        }
        CacheResult::Miss(CacheHandle {
            slot,
            address,
            modules_generation,
        })
    }

    pub fn insert(&mut self, handle: CacheHandle, unwind_rule: UnwindRuleArm64) {
        let CacheHandle {
            slot,
            address,
            modules_generation,
        } = handle;
        self.entries[slot as usize] = Some(CacheEntry {
            address,
            modules_generation,
            unwind_rule,
        });
    }
}

pub enum CacheResult {
    Miss(CacheHandle),
    Hit(Result<u64, Error>),
}

pub struct CacheHandle {
    slot: u16,
    address: u64,
    modules_generation: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct CacheEntry {
    address: u64,
    modules_generation: u16,
    unwind_rule: UnwindRuleArm64,
}
