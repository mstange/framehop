// clear && clang++ -std=c++23 fp-basic-unwind-a64.cc -o fp-basic-unwind-a64 && lldb ./fp-basic-unwind-a64
// A little demo program demonstrating unwinding a jit region without debug information

/*

Dumping the stack using lldb:

bt
p/x $pc
image lookup -a `$pc`
p/x ((void***) $fp)[0][1]
image lookup -a `((void***) $fp)[0][1]`
p/x ((void****) $fp)[0][0][1]
image lookup -a `((void****) $fp)[0][0][1]`
p/x ((void*****) $fp)[0][0][0][1]
image lookup -a `((void*****) $fp)[0][0][0][1]`
p/x ((void******) $fp)[0][0][0][0][1]
image lookup -a `((void******) $fp)[0][0][0][0][1]`

p/x $sp
p/x ((void******) $fp)[0][0][0][0] # Last stack frame

image list
image dump sections

# To get stack bounds:
(gdb) info proc mapping

memory read --outfile ./fp-basic-unwind-a64.stack.bin 0xfffffffdf000 0x1000000000000 --binary --force

 */

#include <cstdio>
#include <bit>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>

extern "C" void breakpoint_mock()
{
    __asm__ volatile (
        "brk #0\n"
    );
}

extern "C" void baseline_mock(uintptr_t baseline_mock_2, uintptr_t breakpoint_mock);
__asm__  (
    "baseline_mock:" "\n"
    "    stp      fp, lr, [sp, #-16]!" "\n"
    "    mov      fp, sp" "\n"
    "    sub      sp, fp, #96" "\n"
    "    movz x16, 0xBEEF" "\n"
    "    stur     x16, [sp]" "\n"
    "    blr      x0" "\n"
    "baseline_mock_2:" "\n"
    "    stp      fp, lr, [sp, #-16]!" "\n"
    "    mov      fp, sp" "\n"
    "    sub      sp, fp, #512" "\n"
    "    movz x16, 0xBFFF" "\n"
    "    stur     x16, [sp]" "\n"
    "    blr      x1" "\n"
);

int main(void)
{
    void* jit = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (jit == (void *) -1)
        return 1;

    printf("Have native stack %p, jit %p\n", __builtin_frame_address(0), jit);

    // baseline_mock((uintptr_t)baseline_mock + 6 * 4, (uintptr_t)breakpoint_mock);
    std::memcpy(jit, (void*) baseline_mock, 1024);

    ((void (*)(uintptr_t, uintptr_t))jit)((uintptr_t)jit + 6 * 4, (uintptr_t)breakpoint_mock);
}
