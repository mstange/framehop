use std::fmt::Debug;

use crate::display_utils::HexNum;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UnwindRegsX86_64 {
    ip: u64,
    sp: u64,
    bp: u64,
}

impl UnwindRegsX86_64 {
    pub fn new(ip: u64, sp: u64, bp: u64) -> Self {
        Self { ip, sp, bp }
    }

    #[inline(always)]
    pub fn ip(&self) -> u64 {
        self.ip
    }
    #[inline(always)]
    pub fn set_ip(&mut self, ip: u64) {
        self.ip = ip
    }

    #[inline(always)]
    pub fn sp(&self) -> u64 {
        self.sp
    }
    #[inline(always)]
    pub fn set_sp(&mut self, sp: u64) {
        self.sp = sp
    }

    #[inline(always)]
    pub fn bp(&self) -> u64 {
        self.bp
    }
    #[inline(always)]
    pub fn set_bp(&mut self, bp: u64) {
        self.bp = bp
    }
}

#[cfg(target_arch = "x86_64")]
pub type UnwindRegsNative = UnwindRegsX86_64;

impl Debug for UnwindRegsX86_64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnwindRegsX86_64")
            .field("sp", &HexNum(self.sp))
            .field("bp", &HexNum(self.bp))
            .finish()
    }
}
