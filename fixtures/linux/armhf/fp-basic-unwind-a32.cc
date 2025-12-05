// clear && clang++ -g -std=c++23 fp-basic-unwind-a32.cc -o fp-basic-unwind-a32 -mthumb -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer && lldb ./fp-basic-unwind-a32
// A little demo program demonstrating unwinding a jit region without debug information

/*

Dumping the stack using lldb:

bt
p/x (uintptr_t)$pc - 0x00400000
image lookup -a `$pc`
p/x ((uintptr_t*) $r7)[1] - 0x00400000
image lookup -a `((void**) $r7)[1]`
p/x ((uintptr_t**) $r7)[0][1] - 0x00400000
image lookup -a `((void***) $r7)[0][1]`
p/x ((uintptr_t***) $r7)[0][0][1] - 0x00400000
image lookup -a `((void****) $r7)[0][0][1]`
p/x ((uintptr_t****) $r7)[0][0][0][1] - 0xf7c8a000
image lookup -a `((void*****) $r7)[0][0][0][1]`
p/x ((uintptr_t*****) $r7)[0][0][0][0][1]
image lookup -a `((void******) $r7)[0][0][0][0][1]`

p/x $sp
p/x ((void******) $r7)[0][0][0][0] # Last stack frame

image list
image dump sections

# To get stack bounds:
(gdb) info proc mapping

memory read --outfile ./fp-basic-unwind-a32.stack.bin 0xfffcf000 0xffff0000 --binary --force

p/x 0xffff0000-$r7
p/x 0xffff0000-$sp
p/x $pc-0x00400000
p/x $lr-0x00400000

 */

#include <cstdio>
#include <bit>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>

__attribute__((target("thumb")))
extern "C" void breakpoint_mock()
{
    __asm__ volatile (
        ".thumb\n"
        ".thumb_func\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "bkpt #0\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
    );
}

__attribute__((target("thumb")))
extern "C" void baseline_mock(uint8_t* baseline_mock_2, uint8_t* breakpoint_mock);
__asm__  (
    ".thumb" "\n"
    ".thumb_func" "\n"
    "baseline_mock:" "\n"
    "    push.w {r7, lr}" "\n"
    "    mov.w r7, sp" "\n"
    "    sub.w sp, #0x20" "\n"
    "    mov r2, 0xBEEF" "\n"
    "    str.w r2, [sp, #4]" "\n"
    "    blx r0" "\n"
    ".thumb" "\n"
    ".thumb_func" "\n"
    "baseline_mock_2:" "\n"
    "    push.w {r7, lr}" "\n"
    "    mov.w r7, sp" "\n"
    "    sub.w sp, #0x28" "\n"
    "    mov r2, 0xBEEF" "\n"
    "    str.w r2, [sp, #4]" "\n"
    "    blx r1" "\n"
);

int main(void)
{
    void* jit = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (jit == (void *) -1)
        return 1;

    printf("Have native stack %p, jit %p\n", __builtin_frame_address(0), jit);

    // baseline_mock((uint8_t*)baseline_mock + 22, (uint8_t*)breakpoint_mock);
    std::memcpy(jit, (void*)((uint8_t*) baseline_mock - 1), 1024);

    ((void (*)(uint8_t*, uint8_t*)) ((uint8_t*)jit + 1))((uint8_t*)jit + 22 + 1, (uint8_t*)breakpoint_mock);
}
