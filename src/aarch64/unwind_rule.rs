use core::fmt::Debug;

use super::unwindregs::{UnwindRegsAarch64, CALLEE_SAVED_COUNT, FIRST_CALLEE_SAVED};
use crate::add_signed::checked_add_signed;
use crate::error::Error;

use crate::unwind_rule::UnwindRule;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameRuleAarch64 {
    /// (sp, fp, lr) = (sp, fp, lr)
    /// Only possible for the first frame. Subsequent frames must get the
    /// return address from somewhere other than the lr register to avoid
    /// infinite loops.
    NoOp,
    /// (sp, fp, lr) = if is_first_frame (sp, fp, lr) else (fp + 16, *fp, *(fp + 8))
    /// Used as a fallback rule.
    NoOpIfFirstFrameOtherwiseFp,
    /// (sp, fp, lr) = (sp + 16x, fp, lr)
    /// Only possible for the first frame. Subsequent frames must get the
    /// return address from somewhere other than the lr register to avoid
    /// infinite loops.
    OffsetSp { sp_offset_by_16: u16 },
    /// (sp, fp, lr) = (sp + 16x, fp, lr) if is_first_frame
    /// This rule reflects an ambiguity in DWARF CFI information. When the
    /// return address is "undefined" because it was omitted, it could mean
    /// "same value", but this is only allowed for the first frame.
    OffsetSpIfFirstFrameOtherwiseStackEndsHere { sp_offset_by_16: u16 },
    /// (sp, fp, lr) = (sp + 16x, fp, *(sp + 8y))
    OffsetSpAndRestoreLr {
        sp_offset_by_16: u16,
        lr_storage_offset_from_sp_by_8: i16,
    },
    /// (sp, fp, lr) = (sp + 16x, *(sp + 8y), *(sp + 8z))
    OffsetSpAndRestoreFpAndLr {
        sp_offset_by_16: u16,
        fp_storage_offset_from_sp_by_8: i16,
        lr_storage_offset_from_sp_by_8: i16,
    },
    /// (sp, fp, lr) = (fp + 16, *fp, *(fp + 8))
    UseFramePointer,
    /// (sp, fp, lr) = (fp + 8x, *(fp + 8y), *(fp + 8z))
    UseFramepointerWithOffsets {
        sp_offset_from_fp_by_8: u16,
        fp_storage_offset_from_fp_by_8: i16,
        lr_storage_offset_from_fp_by_8: i16,
    },
    /// cfa = *(reg + 8w) + 8x
    /// (sp, fp, lr) = (cfa, *(cfa + 8y), *(cfa + 8z))
    /// `reg` is a DWARF register number (x19 - x28, x29, x30 or sp). This is the
    /// shape of the CFA expression of the Android ART nterp interpreter,
    /// `DW_OP_bregx x25 -8; DW_OP_deref; DW_OP_plus_uconst 0xa0`. If `reg` is one of
    /// x19 - x28, its value may be unknown, in which case the rule fails.
    UseDerefedRegister {
        reg: u8,
        reg_offset_by_8: i8,
        cfa_offset_by_8: u16,
        fp_storage_offset_from_cfa_by_8: i8,
        lr_storage_offset_from_cfa_by_8: i8,
    },
}

impl UnwindRule for FrameRuleAarch64 {
    type UnwindRegs = UnwindRegsAarch64;

    fn rule_for_stub_functions() -> Self {
        FrameRuleAarch64::NoOp
    }
    fn rule_for_function_start() -> Self {
        FrameRuleAarch64::NoOp
    }
    fn fallback_rule() -> Self {
        FrameRuleAarch64::UseFramePointer
    }

    fn exec<F>(
        self,
        is_first_frame: bool,
        regs: &mut UnwindRegsAarch64,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let lr = regs.lr();
        let sp = regs.sp();
        let fp = regs.fp();

        let (new_lr, new_sp, new_fp) = match self {
            FrameRuleAarch64::NoOp => {
                if !is_first_frame {
                    return Err(Error::DidNotAdvance);
                }
                (lr, sp, fp)
            }
            FrameRuleAarch64::NoOpIfFirstFrameOtherwiseFp => {
                if is_first_frame {
                    (lr, sp, fp)
                } else {
                    let fp = regs.fp();
                    if fp == 0 {
                        return Ok(None);
                    }
                    let new_sp = fp.checked_add(16).ok_or(Error::IntegerOverflow)?;
                    let new_lr =
                        read_stack(fp + 8).map_err(|_| Error::CouldNotReadStack(fp + 8))?;
                    let new_fp = read_stack(fp).map_err(|_| Error::CouldNotReadStack(fp))?;
                    if new_sp <= sp {
                        return Err(Error::StackPointerMovedBackwards);
                    }
                    (new_lr, new_sp, new_fp)
                }
            }
            FrameRuleAarch64::OffsetSpIfFirstFrameOtherwiseStackEndsHere { sp_offset_by_16 } => {
                if !is_first_frame {
                    return Ok(None);
                }
                let sp_offset = u64::from(sp_offset_by_16) * 16;
                let new_sp = sp.checked_add(sp_offset).ok_or(Error::IntegerOverflow)?;
                (lr, new_sp, fp)
            }
            FrameRuleAarch64::OffsetSp { sp_offset_by_16 } => {
                if !is_first_frame {
                    return Err(Error::DidNotAdvance);
                }
                let sp_offset = u64::from(sp_offset_by_16) * 16;
                let new_sp = sp.checked_add(sp_offset).ok_or(Error::IntegerOverflow)?;
                (lr, new_sp, fp)
            }
            FrameRuleAarch64::OffsetSpAndRestoreLr {
                sp_offset_by_16,
                lr_storage_offset_from_sp_by_8,
            } => {
                let sp_offset = u64::from(sp_offset_by_16) * 16;
                let new_sp = sp.checked_add(sp_offset).ok_or(Error::IntegerOverflow)?;
                let lr_storage_offset = i64::from(lr_storage_offset_from_sp_by_8) * 8;
                let lr_location =
                    checked_add_signed(sp, lr_storage_offset).ok_or(Error::IntegerOverflow)?;
                let new_lr =
                    read_stack(lr_location).map_err(|_| Error::CouldNotReadStack(lr_location))?;
                (new_lr, new_sp, fp)
            }
            FrameRuleAarch64::OffsetSpAndRestoreFpAndLr {
                sp_offset_by_16,
                fp_storage_offset_from_sp_by_8,
                lr_storage_offset_from_sp_by_8,
            } => {
                let sp_offset = u64::from(sp_offset_by_16) * 16;
                let new_sp = sp.checked_add(sp_offset).ok_or(Error::IntegerOverflow)?;
                let lr_storage_offset = i64::from(lr_storage_offset_from_sp_by_8) * 8;
                let lr_location =
                    checked_add_signed(sp, lr_storage_offset).ok_or(Error::IntegerOverflow)?;
                let new_lr =
                    read_stack(lr_location).map_err(|_| Error::CouldNotReadStack(lr_location))?;
                let fp_storage_offset = i64::from(fp_storage_offset_from_sp_by_8) * 8;
                let fp_location =
                    checked_add_signed(sp, fp_storage_offset).ok_or(Error::IntegerOverflow)?;
                let new_fp =
                    read_stack(fp_location).map_err(|_| Error::CouldNotReadStack(fp_location))?;
                (new_lr, new_sp, new_fp)
            }
            FrameRuleAarch64::UseFramePointer => {
                // Do a frame pointer stack walk. Frame-based aarch64 functions store the caller's fp and lr
                // on the stack and then set fp to the address where the caller's fp is stored.
                //
                // Function prologue example (this one also stores x19, x20, x21 and x22):
                // stp  x22, x21, [sp, #-0x30]! ; subtracts 0x30 from sp, and then stores (x22, x21) at sp
                // stp  x20, x19, [sp, #0x10]   ; stores (x20, x19) at sp + 0x10 (== original sp - 0x20)
                // stp  fp, lr, [sp, #0x20]     ; stores (fp, lr) at sp + 0x20 (== original sp - 0x10)
                // add  fp, sp, #0x20           ; sets fp to the address where the old fp is stored on the stack
                //
                // Function epilogue:
                // ldp  fp, lr, [sp, #0x20]     ; restores fp and lr from the stack
                // ldp  x20, x19, [sp, #0x10]   ; restores x20 and x19
                // ldp  x22, x21, [sp], #0x30   ; restores x22 and x21, and then adds 0x30 to sp
                // ret                          ; follows lr to jump back to the caller
                //
                // Functions are called with bl ("branch with link"); bl puts the return address into the lr register.
                // When a function reaches its end, ret reads the return address from lr and jumps to it.
                // On aarch64, the stack pointer is always aligned to 16 bytes, and registers are usually written
                // to and read from the stack in pairs.
                // In frame-based functions, fp and lr are placed next to each other on the stack.
                // So when a function is called, we have the following stack layout:
                //
                //                                                                      [... rest of the stack]
                //                                                                      ^ sp           ^ fp
                //     bl some_function          ; jumps to the function and sets lr = return address
                //                                                                      [... rest of the stack]
                //                                                                      ^ sp           ^ fp
                //     adjust stack ptr, write some registers, and write fp and lr
                //       [more saved regs]  [caller's frame pointer]  [return address]  [... rest of the stack]
                //       ^ sp                                                                          ^ fp
                //     add    fp, sp, #0x20      ; sets fp to where the caller's fp is now stored
                //       [more saved regs]  [caller's frame pointer]  [return address]  [... rest of the stack]
                //       ^ sp               ^ fp
                //     <function contents>       ; can execute bl and overwrite lr with a new value
                //  ...  [more saved regs]  [caller's frame pointer]  [return address]  [... rest of the stack]
                //  ^ sp                    ^ fp
                //
                // So: *fp is the caller's frame pointer, and *(fp + 8) is the return address.
                let fp = regs.fp();
                if fp == 0 {
                    return Ok(None);
                }
                let new_sp = fp.checked_add(16).ok_or(Error::IntegerOverflow)?;
                if new_sp <= sp {
                    return Err(Error::StackPointerMovedBackwards);
                }
                let new_lr = read_stack(fp + 8).map_err(|_| Error::CouldNotReadStack(fp + 8))?;
                let new_fp = read_stack(fp).map_err(|_| Error::CouldNotReadStack(fp))?;
                // new_fp is the caller's fp. If the caller uses frame pointers, it is a
                // valid frame pointer. But the caller may be using fp as a general purpose
                // register, in which case any value (including zero) is valid. We don't
                // know which one it is, so we leave new_fp unchecked, like on x86_64.
                (new_lr, new_sp, new_fp)
            }
            FrameRuleAarch64::UseFramepointerWithOffsets {
                sp_offset_from_fp_by_8,
                fp_storage_offset_from_fp_by_8,
                lr_storage_offset_from_fp_by_8,
            } => {
                let sp_offset_from_fp = u64::from(sp_offset_from_fp_by_8) * 8;
                let new_sp = fp
                    .checked_add(sp_offset_from_fp)
                    .ok_or(Error::IntegerOverflow)?;
                let lr_storage_offset = i64::from(lr_storage_offset_from_fp_by_8) * 8;
                let lr_location =
                    checked_add_signed(fp, lr_storage_offset).ok_or(Error::IntegerOverflow)?;
                let new_lr =
                    read_stack(lr_location).map_err(|_| Error::CouldNotReadStack(lr_location))?;
                let fp_storage_offset = i64::from(fp_storage_offset_from_fp_by_8) * 8;
                let fp_location =
                    checked_add_signed(fp, fp_storage_offset).ok_or(Error::IntegerOverflow)?;
                let new_fp =
                    read_stack(fp_location).map_err(|_| Error::CouldNotReadStack(fp_location))?;
                // As in UseFramePointer, the caller's fp may not be a frame pointer.
                if new_sp <= sp {
                    return Err(Error::StackPointerMovedBackwards);
                }
                (new_lr, new_sp, new_fp)
            }
            FrameRuleAarch64::UseDerefedRegister {
                reg,
                reg_offset_by_8,
                cfa_offset_by_8,
                fp_storage_offset_from_cfa_by_8,
                lr_storage_offset_from_cfa_by_8,
            } => {
                let reg_value = regs
                    .get_reg(u16::from(reg))
                    .ok_or(Error::RegisterValueUnknown)?;
                let cfa_location = checked_add_signed(reg_value, i64::from(reg_offset_by_8) * 8)
                    .ok_or(Error::IntegerOverflow)?;
                let new_sp = read_stack(cfa_location)
                    .map_err(|_| Error::CouldNotReadStack(cfa_location))?
                    .checked_add(u64::from(cfa_offset_by_8) * 8)
                    .ok_or(Error::IntegerOverflow)?;
                if new_sp <= sp {
                    return Err(Error::StackPointerMovedBackwards);
                }
                let lr_location =
                    checked_add_signed(new_sp, i64::from(lr_storage_offset_from_cfa_by_8) * 8)
                        .ok_or(Error::IntegerOverflow)?;
                let new_lr =
                    read_stack(lr_location).map_err(|_| Error::CouldNotReadStack(lr_location))?;
                let fp_location =
                    checked_add_signed(new_sp, i64::from(fp_storage_offset_from_cfa_by_8) * 8)
                        .ok_or(Error::IntegerOverflow)?;
                let new_fp =
                    read_stack(fp_location).map_err(|_| Error::CouldNotReadStack(fp_location))?;
                (new_lr, new_sp, new_fp)
            }
        };
        let return_address = regs.lr_mask().strip_ptr_auth(new_lr);
        if return_address == 0 {
            return Ok(None);
        }
        if !is_first_frame && new_sp == sp {
            return Err(Error::DidNotAdvance);
        }
        regs.set_lr(new_lr);
        regs.set_sp(new_sp);
        regs.set_fp(new_fp);

        Ok(Some(return_address))
    }
}

/// How to recover one of the callee-saved registers x19 - x28 for the caller frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalleeSavedRuleAarch64 {
    /// The caller has the same value as the callee.
    Unchanged,
    /// The value cannot be known, e.g. because the frame was unwound without CFI.
    Unknown,
    /// The value is saved on the stack at CFA + the given (negative) offset in bytes.
    SavedAtCfaOffset(i16),
}

/// Compact recovery rules for x19 - x28, 6 bits per register (bits 6i..6i+6 for
/// x(19 + i)): 0 means unchanged, 63 means unknown, and any other value v means
/// "saved at CFA - 8 * v". The top 4 bits are always zero.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CalleeSavedRulesAarch64(u64);

impl CalleeSavedRulesAarch64 {
    const BITS: u32 = 6;
    const MASK: u64 = (1 << Self::BITS) - 1;
    const UNCHANGED: u64 = 0;
    const UNKNOWN: u64 = Self::MASK;
    const USED_BITS: u64 = (1 << (Self::BITS * CALLEE_SAVED_COUNT as u32)) - 1;

    /// All registers keep their values.
    pub const ALL_UNCHANGED: Self = Self(0);
    /// All registers become unknown.
    pub const ALL_UNKNOWN: Self = Self(Self::USED_BITS);

    fn shift(reg: u16) -> Option<u32> {
        let i = reg.checked_sub(FIRST_CALLEE_SAVED)?;
        (usize::from(i) < CALLEE_SAVED_COUNT).then_some(u32::from(i) * Self::BITS)
    }

    /// The rule for x`reg`, for `reg` in 19..=28.
    pub fn get(&self, reg: u16) -> Option<CalleeSavedRuleAarch64> {
        Some(match (self.0 >> Self::shift(reg)?) & Self::MASK {
            Self::UNCHANGED => CalleeSavedRuleAarch64::Unchanged,
            Self::UNKNOWN => CalleeSavedRuleAarch64::Unknown,
            v => CalleeSavedRuleAarch64::SavedAtCfaOffset(-(v as i16) * 8),
        })
    }

    /// Set the rule for x`reg`, for `reg` in 19..=28. Returns false, and leaves the
    /// rules unchanged, if `reg` is out of range or if the rule is `SavedAtCfaOffset`
    /// with an offset that is not a multiple of 8 within -496..=-8.
    #[must_use]
    pub fn set(&mut self, reg: u16, rule: CalleeSavedRuleAarch64) -> bool {
        let Some(shift) = Self::shift(reg) else {
            return false;
        };
        let v = match rule {
            CalleeSavedRuleAarch64::Unchanged => Self::UNCHANGED,
            CalleeSavedRuleAarch64::Unknown => Self::UNKNOWN,
            CalleeSavedRuleAarch64::SavedAtCfaOffset(offset) => {
                if offset % 8 != 0 || offset >= 0 {
                    return false;
                }
                let v = u64::from(offset.unsigned_abs() / 8);
                if v >= Self::UNKNOWN {
                    return false;
                }
                v
            }
        };
        self.0 = (self.0 & !(Self::MASK << shift)) | (v << shift);
        true
    }

    /// Apply the rules to `regs`, after `regs.sp()` has been set to the CFA.
    #[inline]
    fn apply<F>(self, regs: &mut UnwindRegsAarch64, read_stack: &mut F)
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        if self == Self::ALL_UNCHANGED {
            return;
        }
        if self == Self::ALL_UNKNOWN {
            regs.clear_callee_saved();
            return;
        }
        let cfa = regs.sp();
        for i in 0..CALLEE_SAVED_COUNT {
            let v = (self.0 >> (i as u32 * Self::BITS)) & Self::MASK;
            match v {
                Self::UNCHANGED => {}
                Self::UNKNOWN => regs.set_callee_saved_by_index(i, None),
                v => {
                    let value = cfa
                        .checked_sub(v * 8)
                        .and_then(|addr| read_stack(addr).ok());
                    regs.set_callee_saved_by_index(i, value);
                }
            }
        }
    }
}

impl Debug for CalleeSavedRulesAarch64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if *self == Self::ALL_UNCHANGED {
            return write!(f, "AllUnchanged");
        }
        if *self == Self::ALL_UNKNOWN {
            return write!(f, "AllUnknown");
        }
        let mut list = f.debug_map();
        for i in 0..CALLEE_SAVED_COUNT as u16 {
            let reg = FIRST_CALLEE_SAVED + i;
            match self.get(reg) {
                Some(CalleeSavedRuleAarch64::Unchanged) | None => {}
                Some(rule) => {
                    list.entry(&format_args!("x{reg}"), &rule);
                }
            }
        }
        list.finish()
    }
}

/// The unwind rule which is stored in the unwind rule cache on Aarch64. It combines
/// a [`FrameRuleAarch64`] (for sp, fp and lr) with recovery rules for the callee-saved
/// registers x19 - x28.
///
/// This is 16 bytes, 8-byte aligned, so that copying it out of the cache is cheap.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct UnwindRuleAarch64 {
    frame: FrameRuleAarch64,
    callee_saved: CalleeSavedRulesAarch64,
}

impl UnwindRuleAarch64 {
    /// Create a rule.
    pub fn new(frame: FrameRuleAarch64, callee_saved: CalleeSavedRulesAarch64) -> Self {
        Self {
            frame,
            callee_saved,
        }
    }

    /// The rules for x19 - x28.
    pub(crate) fn callee_saved(&self) -> CalleeSavedRulesAarch64 {
        self.callee_saved
    }
}

impl Debug for UnwindRuleAarch64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnwindRuleAarch64")
            .field("frame", &self.frame)
            .field("callee_saved", &self.callee_saved())
            .finish()
    }
}

impl From<FrameRuleAarch64> for UnwindRuleAarch64 {
    /// Wrap a rule which was not derived from CFI. Only `NoOp` keeps the
    /// callee-saved registers; for other rules we don't know which registers
    /// the callee clobbered.
    fn from(frame: FrameRuleAarch64) -> Self {
        let callee_saved = match frame {
            FrameRuleAarch64::NoOp => CalleeSavedRulesAarch64::ALL_UNCHANGED,
            _ => CalleeSavedRulesAarch64::ALL_UNKNOWN,
        };
        Self {
            frame,
            callee_saved,
        }
    }
}

impl UnwindRule for UnwindRuleAarch64 {
    type UnwindRegs = UnwindRegsAarch64;

    fn rule_for_stub_functions() -> Self {
        FrameRuleAarch64::rule_for_stub_functions().into()
    }
    fn rule_for_function_start() -> Self {
        FrameRuleAarch64::rule_for_function_start().into()
    }
    fn fallback_rule() -> Self {
        FrameRuleAarch64::fallback_rule().into()
    }

    #[inline]
    fn exec<F>(
        self,
        is_first_frame: bool,
        regs: &mut UnwindRegsAarch64,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let result = self.frame.exec(is_first_frame, regs, read_stack);
        if let Ok(Some(_)) = result {
            self.callee_saved().apply(regs, read_stack);
        }
        result
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rule_size() {
        assert_eq!(core::mem::size_of::<FrameRuleAarch64>(), 8);
        assert_eq!(core::mem::size_of::<UnwindRuleAarch64>(), 16);
    }

    #[test]
    fn test_callee_saved_rules() {
        use CalleeSavedRuleAarch64::*;
        let mut rules = CalleeSavedRulesAarch64::ALL_UNCHANGED;
        assert!(rules.set(19, SavedAtCfaOffset(-8)));
        assert!(rules.set(22, SavedAtCfaOffset(-496)));
        assert!(rules.set(28, Unknown));
        assert!(!rules.set(23, SavedAtCfaOffset(-504)));
        assert!(!rules.set(23, SavedAtCfaOffset(i16::MIN)));
        assert!(!rules.set(23, SavedAtCfaOffset(8)));
        assert!(!rules.set(23, SavedAtCfaOffset(-12)));
        assert!(!rules.set(29, Unknown));
        assert_eq!(rules.get(19), Some(SavedAtCfaOffset(-8)));
        assert_eq!(rules.get(22), Some(SavedAtCfaOffset(-496)));
        assert_eq!(rules.get(23), Some(Unchanged));
        assert_eq!(rules.get(28), Some(Unknown));
        assert_eq!(rules.get(18), None);

        let rule = UnwindRuleAarch64::new(FrameRuleAarch64::UseFramePointer, rules);
        assert_eq!(rule.callee_saved(), rules);
    }

    #[test]
    fn test_uncovered_first_frame_clears_callee_saved() {
        let mut regs = UnwindRegsAarch64::new(0x1000, 0x100, 0x200);
        regs.set_callee_saved_from_sample([0x300; CALLEE_SAVED_COUNT]);
        let mut read_stack = |_| Err(());
        let rule = UnwindRuleAarch64::from(FrameRuleAarch64::NoOpIfFirstFrameOtherwiseFp);

        assert_eq!(
            rule.exec(true, &mut regs, &mut read_stack),
            Ok(Some(0x1000))
        );
        for reg in FIRST_CALLEE_SAVED..FIRST_CALLEE_SAVED + CALLEE_SAVED_COUNT as u16 {
            assert_eq!(regs.callee_saved(reg), None);
        }
    }

    #[test]
    fn test_basic() {
        let stack = [
            1, 2, 3, 4, 0x40, 0x100200, 5, 6, 0x70, 0x100100, 7, 8, 9, 10, 0x0, 0x0,
        ];
        let mut read_stack = |addr| Ok(stack[(addr / 8) as usize]);
        let mut regs = UnwindRegsAarch64::new(0x100300, 0x10, 0x20);
        let res = FrameRuleAarch64::NoOp.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(Some(0x100300)));
        assert_eq!(regs.sp(), 0x10);
        let res = FrameRuleAarch64::UseFramePointer.exec(false, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(Some(0x100200)));
        assert_eq!(regs.sp(), 0x30);
        assert_eq!(regs.fp(), 0x40);
        let res = FrameRuleAarch64::UseFramePointer.exec(false, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(Some(0x100100)));
        assert_eq!(regs.sp(), 0x50);
        assert_eq!(regs.fp(), 0x70);
        let res = FrameRuleAarch64::UseFramePointer.exec(false, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(None));
    }

    #[test]
    fn test_zero_fp_ends_stack_without_reading() {
        for rule in [
            FrameRuleAarch64::NoOpIfFirstFrameOtherwiseFp,
            FrameRuleAarch64::UseFramePointer,
        ] {
            let mut regs = UnwindRegsAarch64::new(0x100300, 0x1000, 0);
            let original_regs = regs;
            let mut read_stack =
                |_| -> Result<u64, ()> { panic!("a zero frame pointer should not read the stack") };

            let res = rule.exec(false, &mut regs, &mut read_stack);

            assert_eq!(res, Ok(None));
            assert_eq!(regs, original_regs);
        }
    }

    #[test]
    fn test_caller_without_frame_pointer() {
        // The function at 0x100300 has a frame record at 0x30, as described by
        // its CFI (CFA = fp + 32, fp at CFA - 32, lr at CFA - 24). Its caller
        // doesn't use frame pointers and had 0x8 in x29, which is saved in the
        // frame record and is lower than the current fp.
        let stack = [1, 2, 3, 4, 5, 6, 0x8, 0x100200, 7, 8, 9, 10];
        let mut read_stack = |addr| Ok(stack[(addr / 8) as usize]);
        let mut regs = UnwindRegsAarch64::new(0x100300, 0x10, 0x30);
        let rule = FrameRuleAarch64::UseFramepointerWithOffsets {
            sp_offset_from_fp_by_8: 4,
            fp_storage_offset_from_fp_by_8: 0,
            lr_storage_offset_from_fp_by_8: 1,
        };
        let res = rule.exec(false, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(Some(0x100200)));
        assert_eq!(regs.sp(), 0x50);
        assert_eq!(regs.fp(), 0x8);

        // Same with the standard frame record layout, and a caller with x29 == 0.
        let stack = [1, 2, 3, 4, 5, 6, 0x0, 0x100200, 7, 8];
        let mut read_stack = |addr| Ok(stack[(addr / 8) as usize]);
        let mut regs = UnwindRegsAarch64::new(0x100300, 0x10, 0x30);
        let res = FrameRuleAarch64::UseFramePointer.exec(false, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(Some(0x100200)));
        assert_eq!(regs.sp(), 0x40);
        assert_eq!(regs.fp(), 0x0);
    }
}
