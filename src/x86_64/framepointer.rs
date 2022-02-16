use super::unwind_rule::UnwindRuleX86_64;
use crate::unwind_result::UnwindResult;

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
pub struct FramepointerUnwinderX86_64;

impl FramepointerUnwinderX86_64 {
    pub fn unwind_first(&self) -> UnwindResult<UnwindRuleX86_64> {
        // TODO: Disassemble starting from pc and detect prologue / epiloge

        // For now, just return prologue / epilogue and pretend we're in the middle of a function.
        UnwindResult::ExecRule(UnwindRuleX86_64::UseFramePointer)
    }
}
