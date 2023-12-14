use super::unwindregs::{Reg, UnwindRegsX86_64};
use crate::add_signed::checked_add_signed;
use crate::error::Error;
use crate::unwind_rule::UnwindRule;
use arrayvec::ArrayVec;

/// For all of these: return address is *(new_sp - 8)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnwindRuleX86_64 {
    /// (sp, bp) = (sp + 8, bp)
    JustReturn,
    /// (sp, bp) = if is_first_frame (sp + 8, bp) else (bp + 16, *bp)
    JustReturnIfFirstFrameOtherwiseFp,
    /// (sp, bp) = (sp + 8x, bp)
    OffsetSp { sp_offset_by_8: u16 },
    /// (sp, bp) = (sp + 8x, *(sp + 8y))
    OffsetSpAndRestoreBp {
        sp_offset_by_8: u16,
        bp_storage_offset_from_sp_by_8: i16,
    },
    /// (sp, bp) = (bp + 16, *bp)
    UseFramePointer,
    /// sp = sp + 8 * (offset + register count)
    /// This supports the common case of pushed callee-saved registers followed by a stack
    /// allocation. Up to 8 registers can be stored, which covers all callee-saved registers (aside
    /// from RSP which is implicit).
    ///
    /// The registers are stored in a separate compressed ordering to facilitate restoring register
    /// values if desired. If not for this we could simply store the total offset.
    OffsetSpAndPopRegisters(UnwindRuleOffsetSpAndPopRegisters),
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnwindRuleOffsetSpAndPopRegisters {
    pub sp_offset_by_8: u16,
    registers: u16,
}

pub enum OffsetOrPop {
    None,
    OffsetBy8(u16),
    Pop(Reg),
}

impl UnwindRuleOffsetSpAndPopRegisters {
    const ENCODE_REGISTERS: [Reg; 8] = [
        Reg::RBX,
        Reg::RBP,
        Reg::RDI,
        Reg::RSI,
        Reg::R12,
        Reg::R13,
        Reg::R14,
        Reg::R15,
    ];

    /// Get the rule which represents the given operations, if possible.
    pub fn for_operations<I, T>(iter: I) -> Option<UnwindRuleX86_64>
    where
        I: Iterator<Item = T>,
        T: Into<OffsetOrPop>,
    {
        let mut iter = iter.map(Into::into).peekable();
        let mut rule = Self::default();
        if let Some(OffsetOrPop::OffsetBy8(offset)) = iter.peek() {
            rule.sp_offset_by_8 = *offset;
            iter.next();
        }

        let mut regs = ArrayVec::<Reg, 8>::new();
        for i in iter {
            if let OffsetOrPop::Pop(reg) = i {
                // If try_push errors we've exceeded the number of supported registers: there's no
                // way to encode these operations as an unwind rule.
                regs.try_push(reg).ok()?;
            } else {
                return None;
            }
        }

        if regs.is_empty() && rule.sp_offset_by_8 == 0 {
            Some(UnwindRuleX86_64::JustReturn)
        } else if rule.set_registers(&regs) {
            Some(UnwindRuleX86_64::OffsetSpAndPopRegisters(rule))
        } else {
            None
        }
    }

    /// Return the initial stack pointer offset, in bytes.
    pub fn sp_offset(&self) -> u64 {
        self.sp_offset_by_8 as u64 * 8
    }

    /// Return the ordered set of registers to pop.
    pub fn registers(&self) -> ArrayVec<Reg, 8> {
        let mut regs: ArrayVec<Reg, 8> = Self::ENCODE_REGISTERS.into();
        let mut r = self.registers;
        let mut n: u16 = 8;
        while r != 0 {
            let index = r % n;
            if index != 0 {
                regs[(8 - n as usize)..].swap(index as usize, 0);
            }
            r /= n;
            n -= 1;
        }
        regs.truncate(8 - n as usize);
        regs
    }

    /// Set the ordered registers to pop. Returns true if the registers can be stored.
    pub fn set_registers(&mut self, registers: &[Reg]) -> bool {
        if registers.len() > Self::ENCODE_REGISTERS.len() {
            return false;
        }

        let mut r: u16 = 0;
        let mut reg_order: ArrayVec<Reg, 8> = Self::ENCODE_REGISTERS.into();

        let mut n: u16 = 0;
        let mut scale: u16 = 1;
        for reg in registers {
            let Some(index) = reg_order[n as usize..].iter().position(|r| r == reg) else {
                return false;
            };
            if index as u16 != 0 {
                reg_order[n as usize..].swap(index as usize, 0);
            }
            r += index as u16 * scale;
            scale *= 8 - n;
            n += 1;
        }
        self.registers = r;
        true
    }
}

impl UnwindRule for UnwindRuleX86_64 {
    type UnwindRegs = UnwindRegsX86_64;

    fn rule_for_stub_functions() -> Self {
        UnwindRuleX86_64::JustReturn
    }
    fn rule_for_function_start() -> Self {
        UnwindRuleX86_64::JustReturn
    }
    fn fallback_rule() -> Self {
        UnwindRuleX86_64::UseFramePointer
    }

    fn exec<F>(
        self,
        is_first_frame: bool,
        regs: &mut UnwindRegsX86_64,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let sp = regs.sp();
        let (new_sp, new_bp) = match self {
            UnwindRuleX86_64::JustReturn => {
                let new_sp = sp.checked_add(8).ok_or(Error::IntegerOverflow)?;
                (new_sp, regs.bp())
            }
            UnwindRuleX86_64::JustReturnIfFirstFrameOtherwiseFp => {
                if is_first_frame {
                    let new_sp = sp.checked_add(8).ok_or(Error::IntegerOverflow)?;
                    (new_sp, regs.bp())
                } else {
                    let sp = regs.sp();
                    let bp = regs.bp();
                    let new_sp = bp.checked_add(16).ok_or(Error::IntegerOverflow)?;
                    if new_sp <= sp {
                        return Err(Error::FramepointerUnwindingMovedBackwards);
                    }
                    let new_bp = read_stack(bp).map_err(|_| Error::CouldNotReadStack(bp))?;
                    (new_sp, new_bp)
                }
            }
            UnwindRuleX86_64::OffsetSp { sp_offset_by_8 } => {
                let sp_offset = u64::from(sp_offset_by_8) * 8;
                let new_sp = sp.checked_add(sp_offset).ok_or(Error::IntegerOverflow)?;
                (new_sp, regs.bp())
            }
            UnwindRuleX86_64::OffsetSpAndRestoreBp {
                sp_offset_by_8,
                bp_storage_offset_from_sp_by_8,
            } => {
                let sp_offset = u64::from(sp_offset_by_8) * 8;
                let new_sp = sp.checked_add(sp_offset).ok_or(Error::IntegerOverflow)?;
                let bp_storage_offset_from_sp = i64::from(bp_storage_offset_from_sp_by_8) * 8;
                let bp_location = checked_add_signed(sp, bp_storage_offset_from_sp)
                    .ok_or(Error::IntegerOverflow)?;
                let new_bp = match read_stack(bp_location) {
                    Ok(new_bp) => new_bp,
                    Err(()) if is_first_frame && bp_location < sp => {
                        // Ignore errors when reading beyond the stack pointer in the first frame.
                        // These negative offsets are sometimes seen in x86_64 epilogues, where
                        // a bunch of registers are popped one after the other, and the compiler
                        // doesn't always set the already-popped register to "unchanged" (because
                        // doing so would take up extra space in the dwarf information).
                        // read_stack may legitimately refuse to read beyond the stack pointer,
                        // for example when the stack bytes are coming from a linux perf event
                        // sample record, where the ustack bytes are copied starting from sp.
                        regs.bp()
                    }
                    Err(()) => return Err(Error::CouldNotReadStack(bp_location)),
                };
                (new_sp, new_bp)
            }
            UnwindRuleX86_64::UseFramePointer => {
                // Do a frame pointer stack walk. Code that is compiled with frame pointers
                // has the following function prologues and epilogues:
                //
                // Function prologue:
                // pushq  %rbp
                // movq   %rsp, %rbp
                //
                // Function epilogue:
                // popq   %rbp
                // ret
                //
                // Functions are called with callq; callq pushes the return address onto the stack.
                // When a function reaches its end, ret pops the return address from the stack and jumps to it.
                // So when a function is called, we have the following stack layout:
                //
                //                                                                     [... rest of the stack]
                //                                                                     ^ rsp           ^ rbp
                //     callq some_function
                //                                                   [return address]  [... rest of the stack]
                //                                                   ^ rsp                             ^ rbp
                //     pushq %rbp
                //                         [caller's frame pointer]  [return address]  [... rest of the stack]
                //                         ^ rsp                                                       ^ rbp
                //     movq %rsp, %rbp
                //                         [caller's frame pointer]  [return address]  [... rest of the stack]
                //                         ^ rsp, rbp
                //     <other instructions>
                //       [... more stack]  [caller's frame pointer]  [return address]  [... rest of the stack]
                //       ^ rsp             ^ rbp
                //
                // So: *rbp is the caller's frame pointer, and *(rbp + 8) is the return address.
                //
                // Or, in other words, the following linked list is built up on the stack:
                // #[repr(C)]
                // struct CallFrameInfo {
                //     previous: *const CallFrameInfo,
                //     return_address: *const c_void,
                // }
                // and rbp is a *const CallFrameInfo.
                let sp = regs.sp();
                let bp = regs.bp();
                if bp == 0 {
                    return Ok(None);
                }
                let new_sp = bp.checked_add(16).ok_or(Error::IntegerOverflow)?;
                if new_sp <= sp {
                    return Err(Error::FramepointerUnwindingMovedBackwards);
                }
                let new_bp = read_stack(bp).map_err(|_| Error::CouldNotReadStack(bp))?;
                // new_bp is the caller's bp. If the caller uses frame pointers, then bp should be
                // a valid frame pointer and we could do a coherency check on new_bp to make sure
                // it's moving in the right direction. But if the caller is using bp as a general
                // purpose register, then any value (including zero) would be a valid value.
                // At this point we don't know how the caller uses bp, so we leave new_bp unchecked.

                (new_sp, new_bp)
            }
            UnwindRuleX86_64::OffsetSpAndPopRegisters(r) => {
                let sp = regs.sp();
                let mut sp = sp
                    .checked_add(r.sp_offset())
                    .ok_or(Error::IntegerOverflow)?;
                for reg in r.registers() {
                    let value = read_stack(sp).map_err(|_| Error::CouldNotReadStack(sp))?;
                    sp = sp.checked_add(8).ok_or(Error::IntegerOverflow)?;
                    regs.set(reg, value);
                }
                (sp.checked_add(8).ok_or(Error::IntegerOverflow)?, regs.bp())
            }
        };
        let return_address =
            read_stack(new_sp - 8).map_err(|_| Error::CouldNotReadStack(new_sp - 8))?;
        if return_address == 0 {
            return Ok(None);
        }
        if new_sp == sp && return_address == regs.ip() {
            return Err(Error::DidNotAdvance);
        }
        regs.set_ip(return_address);
        regs.set_sp(new_sp);
        regs.set_bp(new_bp);
        Ok(Some(return_address))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic() {
        let stack = [
            1, 2, 0x100300, 4, 0x40, 0x100200, 5, 6, 0x70, 0x100100, 7, 8, 9, 10, 0x0, 0x0,
        ];
        let mut read_stack = |addr| Ok(stack[(addr / 8) as usize]);
        let mut regs = UnwindRegsX86_64::new(0x100400, 0x10, 0x20);
        let res =
            UnwindRuleX86_64::OffsetSp { sp_offset_by_8: 1 }.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(Some(0x100300)));
        assert_eq!(regs.ip(), 0x100300);
        assert_eq!(regs.sp(), 0x18);
        assert_eq!(regs.bp(), 0x20);
        let res = UnwindRuleX86_64::UseFramePointer.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(Some(0x100200)));
        assert_eq!(regs.ip(), 0x100200);
        assert_eq!(regs.sp(), 0x30);
        assert_eq!(regs.bp(), 0x40);
        let res = UnwindRuleX86_64::UseFramePointer.exec(false, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(Some(0x100100)));
        assert_eq!(regs.ip(), 0x100100);
        assert_eq!(regs.sp(), 0x50);
        assert_eq!(regs.bp(), 0x70);
        let res = UnwindRuleX86_64::UseFramePointer.exec(false, &mut regs, &mut read_stack);
        assert_eq!(res, Ok(None));
    }

    #[test]
    fn test_overflow() {
        // This test makes sure that debug builds don't panic when trying to use frame pointer
        // unwinding on code that was using the bp register as a general-purpose register and
        // storing -1 in it. -1 is u64::MAX, so an unchecked add panics in debug builds.
        let stack = [
            1, 2, 0x100300, 4, 0x40, 0x100200, 5, 6, 0x70, 0x100100, 7, 8, 9, 10, 0x0, 0x0,
        ];
        let mut read_stack = |addr| Ok(stack[(addr / 8) as usize]);
        let mut regs = UnwindRegsX86_64::new(0x100400, u64::MAX / 8 * 8, u64::MAX);
        let res = UnwindRuleX86_64::JustReturn.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Err(Error::IntegerOverflow));
        let res =
            UnwindRuleX86_64::OffsetSp { sp_offset_by_8: 1 }.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Err(Error::IntegerOverflow));
        let res = UnwindRuleX86_64::OffsetSpAndRestoreBp {
            sp_offset_by_8: 1,
            bp_storage_offset_from_sp_by_8: 2,
        }
        .exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Err(Error::IntegerOverflow));
        let res = UnwindRuleX86_64::UseFramePointer.exec(true, &mut regs, &mut read_stack);
        assert_eq!(res, Err(Error::IntegerOverflow));
    }

    #[test]
    fn register_compression() {
        use super::Reg::*;
        let mut v = UnwindRuleOffsetSpAndPopRegisters::default();

        let regs = [RSI, R12, R15, R14, RBX];

        assert!(!v.set_registers(&[RAX]));
        assert!(!v.set_registers(&[RSI, RSI]));
        assert!(v.set_registers(&regs));
        assert_eq!(v.registers().as_slice(), regs);
    }
}
