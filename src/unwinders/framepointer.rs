use crate::unwindregs::UnwindRegsArm64;
use std::result::Result;

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramepointerUnwinderError {
    #[error("The input register set did not have a value for the framepointer register.")]
    NoFramepointerValueProvided,

    #[error("There was a problem reading values from the stack.")]
    CouldNotReadStack,

    #[error("The caller's framepointer wasn't \"higher up\" than this function's framepointer.")]
    FramepointerMovedBackwards,

    #[error("This was the last frame on the stack, indicated by the caller fp being zero.")]
    FoundStackEnd,
}

pub struct FramepointerUnwinderArm64;

impl FramepointerUnwinderArm64 {
    pub fn unwind_next<F>(
        &self,
        regs: &mut UnwindRegsArm64,
        read_mem: &mut F,
    ) -> Result<u64, FramepointerUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        // Do a frame pointer stack walk. Frame-based arm64 functions store the caller's fp and lr
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
        // ldp  x22, x21, [sp], #0x30   ; restores x22 and x21
        // ret                          ; follows lr to jump back to the caller
        //
        // Functions are called with bl ("branch with link"); bl puts the return address into the lr register.
        // When a function reaches its end, ret reads the return address from lr and jumps to it.
        // On arm64, the stack pointer is always aligned to 16 bytes, and registers are usually written
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

        let frame_ptr = regs.fp();
        if frame_ptr == 0 {
            return Err(FramepointerUnwinderError::FoundStackEnd);
        }

        let caller_fp =
            read_mem(frame_ptr).map_err(|_| FramepointerUnwinderError::CouldNotReadStack)?;
        let return_address =
            read_mem(frame_ptr + 8).map_err(|_| FramepointerUnwinderError::CouldNotReadStack)?;

        if caller_fp == 0 {
            return Err(FramepointerUnwinderError::FoundStackEnd);
        }

        // Make sure we don't go backwards in the stack. The stack grows towards
        // lower addresses, so during unwinding we need to move towards higher
        // addresses.
        if caller_fp <= frame_ptr {
            return Err(FramepointerUnwinderError::FramepointerMovedBackwards);
        }

        regs.set_sp(frame_ptr + 16);
        regs.set_fp(caller_fp);
        regs.set_lr(return_address);
        Ok(return_address)
    }
}

// Comment saved here for posterity, it describes x86_64 framepointer stackwalk.
//
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
