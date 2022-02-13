use std::path::Path;

use archunwinders::*;
use fallible_iterator::FallibleIterator;
use framehop::*;

mod common;

#[test]
fn test_basic() {
    let mut cache = CacheAarch64::default();
    let mut unwinder = UnwinderAarch64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/macos/arm64/fp/query-api"),
        0x1003fc000,
    );
    let stack = [
        /* 0x0: */ 1,
        /* 0x8: */ 2,
        /* 0x10: */ 3,
        /* 0x18: */ 4,
        /* 0x20: */ 0x40, // stored fp
        /* 0x28: */ 0x1003fc000 + 0x100dc4, // stored lr
        /* 0x30: */ 5,
        /* 0x38: */ 6,
        /* 0x40: */ 0x70, // stored fp
        /* 0x48: */ 0x1003fc000 + 0x12ca28, // stored lr
        /* 0x50: */ 7,
        /* 0x58: */ 8,
        /* 0x60: */ 9,
        /* 0x68: */ 10,
        /* 0x70: */ 0x0, // sentinel fp
        /* 0x78: */ 0x0, // sentinel lr
    ];
    let mut read_mem = |addr| stack.get((addr / 8) as usize).cloned().ok_or(());
    let mut regs = UnwindRegsAarch64::new(0x1003fc000 + 0xe4830, 0x10, 0x20);
    // There's a frameless function at e0d2c.
    let res = unwinder.unwind_first(0x1003fc000 + 0x1292c0, &mut regs, &mut cache, &mut read_mem);
    assert_eq!(res, Ok(Some(0x1003fc000 + 0xe4830)));
    assert_eq!(regs.sp(), 0x10);
    let res = unwinder.unwind_next(0x1003fc000 + 0xe4830, &mut regs, &mut cache, &mut read_mem);
    assert_eq!(res, Ok(Some(0x1003fc000 + 0x100dc4)));
    assert_eq!(regs.sp(), 0x30);
    assert_eq!(regs.fp(), 0x40);
    let res = unwinder.unwind_next(0x1003fc000 + 0x100dc4, &mut regs, &mut cache, &mut read_mem);
    assert_eq!(res, Ok(Some(0x1003fc000 + 0x12ca28)));
    assert_eq!(regs.sp(), 0x50);
    assert_eq!(regs.fp(), 0x70);
    let res = unwinder.unwind_next(0x1003fc000 + 0x100dc4, &mut regs, &mut cache, &mut read_mem);
    assert_eq!(res, Ok(None));
}

#[test]
fn test_basic_iterator() {
    let mut cache = CacheAarch64::default();
    let mut unwinder = UnwinderAarch64::new();
    common::add_object(
        &mut unwinder,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/macos/arm64/fp/query-api"),
        0x1003fc000,
    );
    let stack = [
        /* 0x0: */ 1,
        /* 0x8: */ 2,
        /* 0x10: */ 3,
        /* 0x18: */ 4,
        /* 0x20: */ 0x40, // stored fp
        /* 0x28: */ 0x1003fc000 + 0x100dc4, // stored lr
        /* 0x30: */ 5,
        /* 0x38: */ 6,
        /* 0x40: */ 0x70, // stored fp
        /* 0x48: */ 0x1003fc000 + 0x12ca28, // stored lr
        /* 0x50: */ 7,
        /* 0x58: */ 8,
        /* 0x60: */ 9,
        /* 0x68: */ 10,
        /* 0x70: */ 0x0, // sentinel fp
        /* 0x78: */ 0x0, // sentinel lr
    ];
    let mut read_mem = |addr| stack.get((addr / 8) as usize).cloned().ok_or(());
    let frames = unwinder
        .iter_frames(
            0x1003fc000 + 0x1292c0,
            UnwindRegsAarch64::new(0x1003fc000 + 0xe4830, 0x10, 0x20),
            &mut cache,
            &mut read_mem,
        )
        .collect();
    assert_eq!(
        frames,
        Ok(vec![
            0x1003fc000 + 0x1292c0,
            0x1003fc000 + 0xe4830,
            0x1003fc000 + 0x100dc4,
            0x1003fc000 + 0x12ca28
        ])
    );
}
