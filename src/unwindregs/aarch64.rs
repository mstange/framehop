use std::fmt::Debug;

use crate::display_utils::HexNum;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UnwindRegsAarch64 {
    lr: u64,
    sp: u64,
    fp: u64,
}

/// On macOS arm64, system libraries are aarch64e binaries, and aarch64e can do pointer authentication:
/// The low bits of the pointer are the actual pointer value, and the high bits are an encrypted hash.
/// During stackwalking, we need to strip off this hash.
/// I don't know of an easy way to get the correct mask dynamically - all the potential functions
/// I've seen for this are no-ops when called from regular aarch64 code.
/// So for now, we hardcode a mask that seems to work today, and worry about it if it stops working.
/// 24 bits hash + 40 bits pointer
const PTR_MASK: u64 = (1 << 40) - 1;

#[inline(always)]
pub fn strip_ptr_auth(ptr: u64) -> u64 {
    ptr & PTR_MASK
}

impl UnwindRegsAarch64 {
    pub fn new(lr: u64, sp: u64, fp: u64) -> Self {
        Self {
            lr: strip_ptr_auth(lr),
            sp: strip_ptr_auth(sp),
            fp: strip_ptr_auth(fp),
        }
    }

    #[inline(always)]
    pub fn sp(&self) -> u64 {
        self.sp
    }
    #[inline(always)]
    pub fn set_sp(&mut self, sp: u64) {
        self.sp = strip_ptr_auth(sp)
    }

    #[inline(always)]
    pub fn fp(&self) -> u64 {
        self.fp
    }
    #[inline(always)]
    pub fn set_fp(&mut self, fp: u64) {
        self.fp = strip_ptr_auth(fp)
    }

    #[inline(always)]
    pub fn lr(&self) -> u64 {
        self.lr
    }
    #[inline(always)]
    pub fn set_lr(&mut self, lr: u64) {
        self.lr = strip_ptr_auth(lr)
    }
}

impl Debug for UnwindRegsAarch64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnwindRegsAarch64")
            .field("lr", &HexNum(self.lr))
            .field("sp", &HexNum(self.sp))
            .field("fp", &HexNum(self.fp))
            .finish()
    }
}
