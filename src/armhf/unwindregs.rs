use core::fmt::Debug;

use crate::display_utils::HexNum;

/// The registers used for unwinding on Armhf. We only need lr (x14), sp (x13),
/// and fp (x11 or x7).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UnwindRegsArmhf {
    lr: u64,
    sp: u64,
    fp: u64,
}

impl UnwindRegsArmhf {
    /// Create a set of unwind register values and do not apply any pointer
    /// authentication stripping.
    pub fn new(lr: u64, sp: u64, fp: u64) -> Self {
        Self { lr, sp, fp }
    }

    /// Get the stack pointer value.
    #[inline(always)]
    pub fn sp(&self) -> u64 {
        self.sp
    }

    /// Set the stack pointer value.
    #[inline(always)]
    pub fn set_sp(&mut self, sp: u64) {
        self.sp = sp
    }

    /// Get the frame pointer value (x29).
    #[inline(always)]
    pub fn fp(&self) -> u64 {
        self.fp
    }

    /// Set the frame pointer value (x29).
    #[inline(always)]
    pub fn set_fp(&mut self, fp: u64) {
        self.fp = fp
    }

    /// Get the lr register value.
    #[inline(always)]
    pub fn lr(&self) -> u64 {
        self.lr
    }

    /// Set the lr register value.
    #[inline(always)]
    pub fn set_lr(&mut self, lr: u64) {
        self.lr = lr
    }
}

impl Debug for UnwindRegsArmhf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnwindRegsArmhf")
            .field("lr", &HexNum(self.lr))
            .field("sp", &HexNum(self.sp))
            .field("fp", &HexNum(self.fp))
            .finish()
    }
}
