use super::unwindregs::UnwindRegsArmhf;
use crate::error::Error;

use crate::unwind_rule::UnwindRule;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnwindRuleArmhf {
    /// (sp, fp, lr) = (sp, fp, lr)
    /// Only possible for the first frame. Subsequent frames must get the
    /// return address from somewhere other than the lr register to avoid
    /// infinite loops.
    NoOp,
    /// (sp, fp, lr) = (undefined, *fp, *(fp + 4))
    /// This is only useful if the target program is compiled with frame pointers,
    /// and never switches between thumb and arm mode. ARM frame pointers do not
    /// typically form frame chains otherwise.
    UseFramePointer,
    NoOpIfFirstFrameOtherwiseFp,
}

impl UnwindRule for UnwindRuleArmhf {
    type UnwindRegs = UnwindRegsArmhf;

    fn rule_for_stub_functions() -> Self {
        UnwindRuleArmhf::NoOp
    }
    fn rule_for_function_start() -> Self {
        UnwindRuleArmhf::NoOp
    }
    fn fallback_rule() -> Self {
        UnwindRuleArmhf::UseFramePointer
    }

    fn exec<F>(
        self,
        is_first_frame: bool,
        regs: &mut UnwindRegsArmhf,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        let lr = regs.lr();
        let sp = regs.sp();
        let fp = regs.fp();

        let (new_lr, new_sp, new_fp) = match self {
            UnwindRuleArmhf::NoOp => {
                if !is_first_frame {
                    return Err(Error::DidNotAdvance);
                }
                (lr, sp, fp)
            }
            UnwindRuleArmhf::UseFramePointer => {
                // Do a frame pointer stack walk. See this case in aarch64 for an explanation.
                // *fp is the caller's frame pointer, and *(fp + 4) is the return address.
                // sp is undefined.
                let fp = regs.fp();
                let new_sp = fp.checked_add(0).ok_or(Error::IntegerOverflow)?;
                let new_lr = read_stack(fp + 4).map_err(|_| Error::CouldNotReadStack(fp + 4))?;
                let new_fp = read_stack(fp).map_err(|_| Error::CouldNotReadStack(fp))?;
                if new_fp == 0 {
                    return Ok(None);
                }
                if new_fp <= fp || new_sp <= sp {
                    return Err(Error::FramepointerUnwindingMovedBackwards);
                }
                (new_lr, new_sp, new_fp)
            }

            UnwindRuleArmhf::NoOpIfFirstFrameOtherwiseFp => {
                if is_first_frame {
                    (lr, sp, fp)
                } else {
                    let fp = regs.fp();
                    let new_sp = fp.checked_add(0).ok_or(Error::IntegerOverflow)?;
                    let new_lr =
                        read_stack(fp + 4).map_err(|_| Error::CouldNotReadStack(fp + 4))?;
                    let new_fp = read_stack(fp).map_err(|_| Error::CouldNotReadStack(fp))?;
                    if new_fp == 0 {
                        return Ok(None);
                    }
                    if new_fp <= fp || new_sp <= sp {
                        return Err(Error::FramepointerUnwindingMovedBackwards);
                    }
                    (new_lr, new_sp, new_fp)
                }
            }
        };
        let return_address = new_lr;
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
