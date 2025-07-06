use std::io::Read;
use std::path::Path;

use framehop::aarch64::*;
use framehop::armhf::*;
use framehop::x86_64::*;
use framehop::FrameAddress;
use framehop::Unwinder;

use super::common;

#[test]
fn test_plt_cfa_expr() {
    let mut cache = CacheX86_64::new();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/linux/x86_64/fp/nightly-firefox-bin"),
        0x1000000,
    );

    // Test some functions from the .plt section. All PLT stubs are covered by one
    // large CFI rule which uses the following DWARF expression to compute the CFA:
    // CFA=reg7 + 8 + (((reg16 & 0xf) >= 0xb) << 3)
    // or, in other words:
    //  - Check the last hex digit of the current instruction address.
    //  - If it's >= b then we've pushed an 8-byte value to the stack, otherwise we
    //    haven't pushed anything.
    //
    //         j_ceil:        // ceil
    // c0d0         jmp        qword [ceil@GOT]
    //          sub_c0d6:
    // c0d6         push       0xa
    // c0db         jmp        0xc020
    //         j_sprintf:        // sprintf
    // c0e0         jmp        qword [sprintf@GOT]
    //         sub_c0e6:
    // c0e6         push       0xb
    // c0eb         jmp        0xc020

    // return address 0x123456 is at stack location 0x30.
    let stack = [1, 2, 3, 4, 5, 0xa, 0x123456, 6, 7, 8, 9];
    let mut read_stack = |addr| stack.get((addr / 8) as usize).cloned().ok_or(());

    for (sp, rel_pc) in [
        (0x28, 0xc0db),
        (0x30, 0xc0e0),
        (0x30, 0xc0e6),
        (0x28, 0xc0eb),
    ]
    .iter()
    {
        let mut regs = UnwindRegsX86_64::new(0x1000000 + rel_pc, *sp, 0x345);
        let res = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(0x1000000 + rel_pc),
            &mut regs,
            &mut cache,
            &mut read_stack,
        );
        assert_eq!(res, Ok(Some(0x123456)));
        assert_eq!(regs.sp(), 0x38);
        assert_eq!(regs.bp(), 0x345);
    }
}

#[test]
fn test_pthread_cfa_expr() {
    let mut cache = CacheX86_64::<_>::new();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/linux/x86_64/nofp/libpthread-2.19.so"),
        0x7f54b14fc000,
    );

    // ...
    // _L_lock_4767:
    // 9423  lea  rdi, qword [stack_cache_lock]
    // 942a  sub  rsp, 0x80
    // 9431  call  __lll_lock_wait_private
    // 9436  add  rsp, 0x80
    // 943d  jmp  loc_8c2c
    // _L_unlock_4791:
    // ...
    //
    // with DWARF CFI:
    //
    // 0x9423: CFA=reg7-128: reg16=DW_OP_breg16 +19 // 0x9423 + 19 == 0x9436
    // 0x942a: CFA=reg7-128: reg16=DW_OP_breg16 +12 // 0x942a + 12 == 0x9436
    // 0x9431: CFA=reg7: reg16=DW_OP_breg16 +5 // 0x9431 + 5 == 0x9436
    // 0x9435: CFA=reg7+128: reg16=DW_OP_breg16 +6, DW_OP_const4s -45616, DW_OP_minus, DW_OP_const4s -47680, DW_OP_plus
    // 0x943d: CFA=reg7-128: reg16=DW_OP_breg16 -7 // 0x943d - 7 == 0x9436
    //
    // This is some super weird stuff. So basically, all addresses other than the add instruction "unwind" by jumping
    // to the add instruction. And then from there, you unwind by adding and subtracting some literals to rip.
    // CFA=reg7+128: reg16=rip + 6 - -45616 + -47680 (== 0x8c2c)
    //
    // Yes, indeed, 0x8c2c seems like the right target address:
    //
    // pthread_create@@GLIBC_2.2.5:
    // 8430  push  rbp
    // ...
    // 8c1e  lock cmpxchg dword [stack_cache_lock], esi
    // 8c26  jne  _L_lock_4767                    ; <-- _L_lock_4767 is function we just unwound from
    // 8c2c  mov  rdx, qword [__stack_user]       ; <-- this is the return address we unwound to
    // 8c33  lea  rax, qword [r15+0x2c0]
    // ...
    //
    let mut stack = vec![0u64; 0x200 / 8];
    stack[0x120 / 8] = 0x1234;
    stack[0x128 / 8] = 0xbe7042;
    let mut read_stack = |addr| stack.get((addr / 8) as usize).cloned().ok_or(());
    let mut regs = UnwindRegsX86_64::new(0x7f54b14fc000 + 0x9431, 0x10, 0x120);

    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x7f54b14fc000 + 0x9431),
        &mut regs,
        &mut cache,
        &mut read_stack,
    );
    assert_eq!(res, Ok(Some(0x7f54b14fc000 + 0x9436)));
    assert_eq!(regs.sp(), 0x10);
    assert_eq!(regs.bp(), 0x120);

    let res = unwinder.unwind_frame(
        FrameAddress::from_return_address(0x7f54b14fc000 + 0x9436).unwrap(),
        &mut regs,
        &mut cache,
        &mut read_stack,
    );
    assert_eq!(res, Ok(Some(0x7f54b14fc000 + 0x8c2c)));
    assert_eq!(regs.sp(), 0x90);
    assert_eq!(regs.bp(), 0x120);

    // 0x88e8: CFA=reg7+8: reg3=[CFA-56], reg6=[CFA-16], reg12=[CFA-48], reg13=[CFA-40], reg14=[CFA-32], reg15=[CFA-24], reg16=[CFA-8]
    // This is a frame pointer unwind!
    let res = unwinder.unwind_frame(
        FrameAddress::from_return_address(0x7f54b14fc000 + 0x8c2c).unwrap(),
        &mut regs,
        &mut cache,
        &mut read_stack,
    );
    assert_eq!(res, Ok(Some(0xbe7042)));
    assert_eq!(regs.sp(), 0x130);
    assert_eq!(regs.bp(), 0x1234);
}

#[test]
fn test_no_eh_frame_hdr() {
    let mut cache = CacheAarch64::<_>::new();
    let mut unwinder = UnwinderAarch64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/linux/aarch64/vdso.so"),
        0x0,
    );
    let mut stack = [
        /* 0x0: */ 0, /* 0x8: */ 1, /* 0x10: */ 2, /* 0x18: */ 3,
        /* 0x20: */ 40000, // stored fp
        /* 0x28: */ 50000, // stored lr
        /* 0x30: */ 6, /* 0x38: */ 7, /* 0x40: */ 80000, // stored fp
        /* 0x48: */ 90000, // stored lr
        /* 0x50: */ 10, /* 0x58: */ 11, /* 0x60: */ 12, /* 0x68: */ 13,
        /* 0x70: */ 0x0, // sentinel fp
        /* 0x78: */ 0x0, // sentinel lr
    ];
    let mut regs = UnwindRegsAarch64::new(0x1234, 0x50, 0x70);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x5a8),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x1234)));
    assert_eq!(regs.sp(), 0x50);
    assert_eq!(regs.fp(), 0x70);
    assert_eq!(regs.lr(), 0x1234);

    let mut regs = UnwindRegsAarch64::new(0x1234, 0x40, 0x70);
    stack[8] = regs.fp();
    stack[9] = regs.lr();
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x5ac),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x1234)));
    assert_eq!(regs.sp(), 0x50);
    assert_eq!(regs.fp(), 0x70);
    assert_eq!(regs.lr(), 0x1234);

    let mut regs = UnwindRegsAarch64::new(0x1234, 0x40, 0x40);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x5b0),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x1234)));
    assert_eq!(regs.sp(), 0x50);
    assert_eq!(regs.fp(), 0x70);
    assert_eq!(regs.lr(), 0x1234);

    let mut regs = UnwindRegsAarch64::new(0x5b4, 0x40, 0x40);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x3c0),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x5b4)));
    assert_eq!(regs.sp(), 0x40);
    assert_eq!(regs.fp(), 0x40);
    assert_eq!(regs.lr(), 0x5b4);

    let mut regs = UnwindRegsAarch64::new(0x5b4, 0x40, 0x40);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x3c0),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x5b4)));
    assert_eq!(regs.sp(), 0x40);
    assert_eq!(regs.fp(), 0x40);
    assert_eq!(regs.lr(), 0x5b4);

    let mut regs = UnwindRegsAarch64::new(0x5b4, 0x40, 0x40);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x3ec),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x5b4)));
    assert_eq!(regs.sp(), 0x40);
    assert_eq!(regs.fp(), 0x40);
    assert_eq!(regs.lr(), 0x5b4);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x5b4),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x1234)));
    assert_eq!(regs.sp(), 0x50);
    assert_eq!(regs.fp(), 0x70);
    assert_eq!(regs.lr(), 0x1234);

    let mut regs = UnwindRegsAarch64::new(0x1234, 0x50, 0x70);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x5b8),
        &mut regs,
        &mut cache,
        &mut |addr| stack.get((addr / 8) as usize).cloned().ok_or(()),
    );
    assert_eq!(res, Ok(Some(0x1234)));
    assert_eq!(regs.sp(), 0x50);
    assert_eq!(regs.fp(), 0x70);
    assert_eq!(regs.lr(), 0x1234);
}

#[test]
fn test_epilogue_bp_already_popped() {
    let mut cache = CacheX86_64::<_>::new();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/linux/x86_64/nofp/rustup"),
        0x0,
    );

    // ...
    // 583a11  add  rsp, 0x128
    // 583a18  pop  rbx
    // 583a19  pop  r14
    // 583a1b  pop  r15
    // 583a1d  pop  rbp
    // 583a1e  ret               ; <-- profiler sampled here, bp already popped
    // 583a1f  xorps xmm0, xmm0
    // ...
    //
    // DWARF CFI:
    // ...
    // 0x583a18: CFA=RSP+40: RBX=[CFA-40], RBP=[CFA-16], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]
    // 0x583a19: CFA=RSP+32: RBX=[CFA-40], RBP=[CFA-16], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]
    // 0x583a1b: CFA=RSP+24: RBX=[CFA-40], RBP=[CFA-16], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]
    // 0x583a1d: CFA=RSP+16: RBX=[CFA-40], RBP=[CFA-16], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]
    // 0x583a1e: CFA=RSP+8: RBX=[CFA-40], RBP=[CFA-16], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]
    // 0x583a1f: CFA=RSP+336: RBX=[CFA-40], RBP=[CFA-16], R14=[CFA-32], R15=[CFA-24], RIP=[CFA-8]
    // ...
    //
    // Note the "CFA=RSP+8: RBX=[CFA-40], RBP=[CFA-16]" - the dwarf cfi is referring to registers
    // that are stored on the stack at locations beyond the current stack pointer value.
    //
    // We don't need to read those registers; we've already popped them so they're already in
    // the "pre-unwind" register values.

    // sp = 0x330
    // return address 0x123456 is at stack location 0x330.
    let mut read_stack = |addr| {
        if addr < 0x330 {
            return Err(());
        }
        if addr == 0x330 {
            return Ok(0x123456);
        };
        Ok(addr - 0x330)
    };

    // The correct value for bp is already in the bp register, we're just
    // past the instruction that popped the value.
    let mut regs = UnwindRegsX86_64::new(0x583a1e, 0x330, 0x348);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x583a1e),
        &mut regs,
        &mut cache,
        &mut read_stack,
    );
    assert_eq!(res, Ok(Some(0x123456)));
    assert_eq!(regs.sp(), 0x338);
    assert_eq!(regs.bp(), 0x348);
}

#[test]
fn test_libc_syscall_no_fde() {
    let mut cache = CacheX86_64::<_>::new();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/linux/x86_64/nofp/libc.so.6"),
        0x0,
    );

    // sub_129720:
    // 129720  endbr64                      ; End of unwind block (FDE at 0x206a24), Begin of unwind block (FDE at 0x206a6c)
    // 129724  mov        eax, 0xffffffea
    // 129729  test       rdi, rdi
    // 12972c  je         loc_12975a
    // 12972e  test       rdx, rdx
    // 129731  je         loc_12975a
    // 129733  mov        r8, rcx
    // 129736  mov        eax, 0x1b3
    // 12973b  syscall                      ; End of unwind block (FDE at 0x206a6c)
    // 12973d  test       rax, rax    ; <-- profiler sampled here
    // 129740  jl         loc_12975a
    // 129742  je         loc_129745
    // 129744  ret
    // 129745  xor        ebp, ebp
    // ...

    // There is no FDE covering the sampled instruction.

    // sp = 0x330
    // return address 0x123456 is at stack location 0x330.
    let mut read_stack = |addr| {
        if addr < 0x330 {
            return Err(());
        }
        if addr == 0x330 {
            return Ok(0x123456);
        };
        Ok(addr - 0x330)
    };

    // The correct value for bp is already in the bp register, we're just
    // past the instruction that popped the value.
    let mut regs = UnwindRegsX86_64::new(0x12973d, 0x330, 0x348);
    let res = unwinder.unwind_frame(
        FrameAddress::from_instruction_pointer(0x12973d),
        &mut regs,
        &mut cache,
        &mut read_stack,
    );
    assert_eq!(res, Ok(Some(0x123456)));
    assert_eq!(regs.sp(), 0x338);
    assert_eq!(regs.bp(), 0x348);
}

#[test]
fn test_root_func_x64() {
    let mut cache = CacheX86_64::<_>::new();
    let mut unwinder = UnwinderX86_64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/linux/x86_64/nofp/release-firefox-bin"),
        0x0,
    );

    // _start:
    // 88cc9  xor   ebp, ebp
    // 88ccb  mov   r9, rdx
    // 88cce  pop   rsi
    // 88ccf  mov   rdx, rsp
    // 88cd2  and   rsp, 0xfffffffffffffff0
    // 88cd6  push  rax
    // 88cd7  push  rsp
    // 88cd8  lea   r8, qword [__libc_csu_fini]
    // 88cdf  lea   rcx, qword [__libc_csu_init]
    // 88ce6  lea   rdi, qword [sub_88de0]
    // 88ced  call  j___libc_start_main
    // 88cf2  hlt                                  ; <-- callee return address
    //
    // DWARF CFI:
    //
    // 00000018 00000014 0000001c FDE cie=00000000 pc=00088cc9...00088cf3
    // Format:       DWARF32
    // DW_CFA_nop:
    // DW_CFA_nop:
    // DW_CFA_nop:
    // DW_CFA_nop:
    // DW_CFA_nop:
    // DW_CFA_nop:
    // DW_CFA_nop:
    //
    // 0x88cc9: CFA=RSP+8: RIP=undefined

    // sp = 0x1000
    let mut read_stack = |addr| {
        if addr >= 0x1000 {
            Ok(0x123456)
        } else {
            Err(())
        }
    };

    // Unwinding should stop immediately and not even read from the stack.
    let mut regs = UnwindRegsX86_64::new(0x88cf2, 0x1000, 0xbeef);
    let res = unwinder.unwind_frame(
        FrameAddress::from_return_address(0x88cf2).unwrap(),
        &mut regs,
        &mut cache,
        &mut read_stack,
    );
    assert_eq!(res, Ok(None));
}

#[ignore] // currently fails
#[test]
fn test_root_func_aarch64_old_glibc() {
    // This test checks that we correctly stop unwinding at the root function (`start`)
    // in aarch64 Linux binaries which were linked with an old glibc (2.18 and older).
    // The `rustup` binary used for this test was compiled with glibc 2.17, so that it
    // can run on old Linux systems, see https://github.com/rust-lang/rustup/issues/1681 .
    //
    // The `start` function is statically linked from glibc at compile time, so its contents
    // depend on the version of glibc used on the machine that does the linking.
    // In glibc versions prior to 2.19, the beginning of the aarch64 `start` function looked like this:
    //
    // ```asm
    // _start:
    // mov fp, #0x0  ; <-- sets fp to 0x0
    // mov lr, #0x0
    // mov fp, sp    ; <-- overwrites fp with sp, removed in glibc 2.19
    // mov x5, x0
    // [...]
    // ```
    //
    // The instruction "mov fp, sp" was unnecessary and made it so that the framepointer
    // register was set to a garbage value (https://sourceware.org/bugzilla/show_bug.cgi?id=17555 ).
    // This was fixed in 2014 in glibc 2.19 - the offending instruction was removed. However,
    // by building with old glibc versions, binaries built today still ship with this bug.
    //
    // Due to the wrong value of fp, the stack end is not detected correctly and we unwind
    // one more frame, getting a garbage address as the caller of `start`.
    // In a profiler, an extraneous caller of the root frame is usually easy ignore.
    // But there are cases where having such an additional root frame can be quite annoying,
    // for example when merging multiple runs into a single profile: https://share.firefox.dev/4aY3gUF
    // This profile was obtained with the following command:
    // `samply record --iteration-count 10 --reuse-threads rustup check`
    // The extra "caller" of `start` is a different address in every run, and the combined
    // flame graph of the multiple run doesn't "combine" correctly. Instead, you get 10
    // different flamegraph "roots", each for a different garbage address.
    //
    // Aside: I first thought that all Rust binaries which link with the prebuilt stdlib
    // would have this bug, since the Rust stdlib currently links with glibc 2.17:
    // https://blog.rust-lang.org/2022/08/01/Increasing-glibc-kernel-requirements.html
    // However, a Rust binary compiled on my machine with glibc 2.35 does not have the
    // bad instruction in its `start` function. So it seems the stdlib doesn't provide
    // the `start` function.

    let mut cache = CacheAarch64::<_>::new();
    let mut unwinder = UnwinderAarch64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/linux/aarch64/rustup"),
        0xaaaaaaaa0000,
    );

    // _start:
    // e6868  mov  fp, #0x0          ; <-- sets fp to 0x0
    // e686c  mov  lr, #0x0
    // e6870  mov  fp, sp            ; <-- overwrites fp with sp, removed in glibc 2.19
    // e6874  mov  x5, x0
    // e6878  ldr  x1, [sp, 0]
    // e687c  add  x2, sp, #0x8
    // e6880  mov  x6, sp
    // e6884  adrp  x0, #0x98d000
    // e6888  ldr  x0, [x0, #0xfe8]
    // e688c  adrp  x3, #0x98d000
    // e6890  ldr  x3, [x3, #0xbf8]
    // e6894  adrp  x4, #0x98d000
    // e6898  ldr  x4, [x4, #0x730]
    // e689c  bl  sub_c70a0
    // e68a0  bl  sub_c7540            ; <-- callee return address
    // e68a4  adrp  x0, #0x98d000
    // e68a8  ldr  x0, [x0, #0x810]
    // e68ac  cbz  x0, loc_e68b4
    // e68b0  b  sub_c71a0
    // e68b4  ret

    // DWARF CFI: Nothing! This function is not covered by any FDE.
    // It falls between init_cpu_feature (pc=000e6820...000e6868) and
    // deregister_tm_clones (pc=000e68b8...000e68e4)

    // sp = 0x0000fffffffff080
    let mut read_stack = |addr| {
        Ok(match addr {
            0x0000fffffffff080 => 0x0000000000000002,
            0x0000fffffffff088 => 0xffffc8936f0f,
            _ => return Err(()),
        })
    };

    // Unwinding should stop immediately and not even read from the stack.
    let mut regs =
        UnwindRegsAarch64::new(0x0000aaaaaab868a0, 0x0000fffffffff080, 0x0000fffffffff080);
    let res = unwinder.unwind_frame(
        FrameAddress::from_return_address(0x0000aaaaaab868a0).unwrap(),
        &mut regs,
        &mut cache,
        &mut read_stack,
    );
    assert_eq!(res, Ok(None));
}

#[test]
fn fp_basic_unwind_a64() {
    use framehop::MayAllocateDuringUnwind;

    let mut cache = CacheAarch64::<_>::new();
    let mut unwinder = UnwinderAarch64::<Vec<u8>, MayAllocateDuringUnwind>::new();

    let mut stack_bytes = Vec::new();
    let mut file = std::fs::File::open(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/linux/aarch64/fp-basic-unwind-a64.stack.bin"),
    )
    .unwrap();
    file.read_to_end(&mut stack_bytes).unwrap();
    assert!(stack_bytes.len() % 8 == 0);
    let stack = stack_bytes
        .chunks(8)
        .map(|x| x.try_into().unwrap())
        .map(u64::from_le_bytes)
        .collect::<Vec<_>>();

    let module = framehop::Module::new(
        "basic-a64".to_string(),
        0x0000aaaaaaaa0000..0x0000aaaaaaac0048,
        0x0000aaaaaaaa0000,
        framehop::ExplicitModuleSectionInfo {
            ..Default::default()
        },
    );
    unwinder.add_module(module);

    let pc = 0x0000aaaaaaaa0000 + 0x0000000000000858;
    let lr = 0x0000aaaaaaaa0000 + 0x0000000000000858;
    let sp = 0x1000000000000 - 0x0000000000000c50;
    let fp = 0x1000000000000 - 0x0000000000000a50;
    let mut read_stack = |addr| {
        assert!(addr % 8 == 0);
        assert!(addr <= 0x1000000000000);
        let offset = (0x1000000000000 - addr) as usize / 8;
        assert!(offset < stack.len());
        stack.get(stack.len() - offset).cloned().ok_or(())
    };

    use framehop::Unwinder;
    let mut iter = unwinder.iter_frames(
        pc,
        UnwindRegsAarch64::new(lr, sp, fp),
        &mut cache,
        &mut read_stack,
    );

    let mut frames = Vec::new();
    while let Ok(Some(frame)) = iter.next() {
        frames.push(frame);
    }

    assert_eq!(
        frames,
        vec![
            FrameAddress::from_instruction_pointer(0x0000aaaaaaaa0000 + 0x0000000000000858),
            FrameAddress::from_return_address(0x0000aaaaaaaa0000 + 0x0000000000000840).unwrap(),
            FrameAddress::from_return_address(0x0000aaaaaaaa0000 + 0x00000000000008e8).unwrap(),
            FrameAddress::from_return_address(0x0000fffff7a60000 + 0x00000000000284c4).unwrap(),
            FrameAddress::from_return_address(0x0000fffff7a60000 + 0x0000000000028598).unwrap(),
        ]
    );
}

#[test]
fn fp_basic_unwind_a64_jit() {
    use framehop::MayAllocateDuringUnwind;

    let mut cache = CacheAarch64::<_>::new();
    let mut unwinder = UnwinderAarch64::<Vec<u8>, MayAllocateDuringUnwind>::new();

    let mut stack_bytes = Vec::new();
    let mut file = std::fs::File::open(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/linux/aarch64/fp-basic-unwind-a64-jit.stack.bin"),
    )
    .unwrap();
    file.read_to_end(&mut stack_bytes).unwrap();
    assert!(stack_bytes.len() % 8 == 0);
    let stack = stack_bytes
        .chunks(8)
        .map(|x| x.try_into().unwrap())
        .map(u64::from_le_bytes)
        .collect::<Vec<_>>();

    let module = framehop::Module::new(
        "basic-a64".to_string(),
        0x0000aaaaaaaa0000..0x0000aaaaaaac0048,
        0x0000aaaaaaaa0000,
        framehop::ExplicitModuleSectionInfo {
            ..Default::default()
        },
    );
    unwinder.add_module(module);

    let pc = 0x0000aaaaaaaa0000 + 0x0000000000000898;
    let lr = 0xfffff7ff1000 + 0x000000000000030;
    let sp = 0x1000000000000 - 0x0000000000000c50;
    let fp = 0x1000000000000 - 0x0000000000000a50;
    let mut read_stack = |addr| {
        assert!(addr % 8 == 0);
        assert!(addr <= 0x1000000000000);
        let offset = (0x1000000000000 - addr) as usize / 8;
        assert!(offset < stack.len());
        stack.get(stack.len() - offset).cloned().ok_or(())
    };

    use framehop::Unwinder;
    let mut iter = unwinder.iter_frames(
        pc,
        UnwindRegsAarch64::new(lr, sp, fp),
        &mut cache,
        &mut read_stack,
    );

    let mut frames = Vec::new();
    while let Ok(Some(frame)) = iter.next() {
        frames.push(frame);
    }

    println!(
        "{:?}",
        frames
            .iter()
            .map(|frame| format!("{:x}", frame.address()))
            .collect::<Vec<String>>()
    );
    assert_eq!(
        frames,
        vec![
            FrameAddress::from_instruction_pointer(0x0000aaaaaaaa0000 + 0x0000000000000898),
            FrameAddress::from_return_address(0xfffff7ff1000 + 0x0000000000000018).unwrap(),
            FrameAddress::from_return_address(0x0000aaaaaaaa0000 + 0x0000000000000934).unwrap(),
            FrameAddress::from_return_address(0x0000fffff7a60000 + 0x00000000000284c4).unwrap(),
            FrameAddress::from_return_address(0x0000fffff7a60000 + 0x0000000000028598).unwrap(),
        ]
    );
}

#[test]
fn fp_basic_unwind_a32() {
    use framehop::MayAllocateDuringUnwind;

    let mut cache = CacheArmhf::<_>::new();
    let mut unwinder = UnwinderArmhf::<Vec<u8>, MayAllocateDuringUnwind>::new();

    let mut stack_bytes = Vec::new();
    let mut file = std::fs::File::open(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/linux/armhf/fp-basic-unwind-a32.stack.bin"),
    )
    .unwrap();
    file.read_to_end(&mut stack_bytes).unwrap();
    assert!(stack_bytes.len() % 4 == 0);
    let stack = stack_bytes
        .chunks(4)
        .map(|x| x.try_into().unwrap())
        .map(u32::from_le_bytes)
        .collect::<Vec<_>>();

    let module = framehop::Module::new(
        "basic-a32".to_string(),
        0x00400000..0x00400000,
        0x00400000,
        framehop::ExplicitModuleSectionInfo {
            ..Default::default()
        },
    );
    unwinder.add_module(module);

    let pc = 0x00400000 + 0x0000060e;
    let lr = 0x00400000 + 0x00000609;
    let sp = 0xffff0000 - 0x00000938;
    let fp = 0xffff0000 - 0x00000910;
    let mut read_stack = |addr| {
        assert!(addr % 4 == 0);
        assert!(addr < 0xffff0000);
        let offset = ((0xffff0000 - addr) / 4) as usize;
        assert!(offset < stack.len());
        stack
            .get(stack.len() - offset)
            .cloned()
            .ok_or(())
            .map(|x| x as u64)
    };

    use framehop::Unwinder;
    let mut iter = unwinder.iter_frames(
        pc,
        UnwindRegsArmhf::new(lr, sp, fp),
        &mut cache,
        &mut read_stack,
    );

    let mut frames = Vec::new();
    while let Ok(Some(frame)) = iter.next() {
        frames.push(frame);
    }

    assert_eq!(
        frames,
        vec![
            FrameAddress::from_instruction_pointer(0x00400000 + 0x0000060e),
            FrameAddress::from_return_address(0x00400000 + 0x000005f3).unwrap(),
            FrameAddress::from_return_address(0x00400000 + 0x0000066d).unwrap(),
        ]
    );
}

#[test]
fn fp_basic_unwind_a32_jit() {
    use framehop::MayAllocateDuringUnwind;

    let mut cache = CacheArmhf::<_>::new();
    let mut unwinder = UnwinderArmhf::<Vec<u8>, MayAllocateDuringUnwind>::new();

    let mut stack_bytes = Vec::new();
    let mut file = std::fs::File::open(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/linux/armhf/fp-basic-unwind-a32-jit.stack.bin"),
    )
    .unwrap();
    file.read_to_end(&mut stack_bytes).unwrap();
    assert!(stack_bytes.len() % 4 == 0);
    let stack = stack_bytes
        .chunks(4)
        .map(|x| x.try_into().unwrap())
        .map(u32::from_le_bytes)
        .collect::<Vec<_>>();

    let module = framehop::Module::new(
        "basic-a32".to_string(),
        0x00400000..0x00400000,
        0x00400000,
        framehop::ExplicitModuleSectionInfo {
            ..Default::default()
        },
    );
    unwinder.add_module(module);

    let pc = 0x00400000 + 0x0000060e;
    let lr = 0xf7fcf000 + 0x0000002d;
    let sp = 0xffff0000 - 0x00000930;
    let fp = 0xffff0000 - 0x00000908;
    let mut read_stack = |addr| {
        assert!(addr % 4 == 0);
        assert!(addr <= 0xffff0000);
        let offset = (0xffff0000 - addr) as usize / 4;
        assert!(offset < stack.len());
        stack
            .get(stack.len() - offset)
            .cloned()
            .ok_or(())
            .map(|x| x as u64)
    };

    use framehop::Unwinder;
    let mut iter = unwinder.iter_frames(
        pc,
        UnwindRegsArmhf::new(lr, sp, fp),
        &mut cache,
        &mut read_stack,
    );

    let mut frames = Vec::new();
    while let Ok(Some(frame)) = iter.next() {
        println!("{:x}", frame.address());
        frames.push(frame);
    }

    assert_eq!(
        frames,
        vec![
            FrameAddress::from_instruction_pointer(0x00400000 + 0x0000060e),
            FrameAddress::from_return_address(0xf7fcf000 + 0x00000017).unwrap(),
            FrameAddress::from_return_address(0x00400000 + 0x00000677).unwrap(),
        ]
    );
}
