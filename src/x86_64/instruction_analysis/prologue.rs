use super::super::unwind_rule::UnwindRuleX86_64;

pub fn unwind_rule_from_detected_prologue(
    text_bytes: &[u8],
    pc_offset: usize,
) -> Option<UnwindRuleX86_64> {
    let (slice_from_start, slice_to_end) = text_bytes.split_at(pc_offset);
    if !is_next_instruction_expected_in_prologue(slice_to_end) {
        return None;
    }
    // We're in a prologue. Find the current stack depth of this frame by
    // walking backwards. This is risky business, because x86 is a variable
    // length encoding so you never know what you're looking at if you look
    // backwards.
    // Let's do it anyway and hope our heuristics are good enough so that
    // they work in more cases than they fail in.
    let mut cursor = slice_from_start.len();
    let mut sp_offset_by_8 = 0;
    loop {
        if cursor >= 4 {
            // Detect push rbp; mov rbp, rsp [0x55, 0x48 0x89 0xe5]
            if slice_from_start[cursor - 4..cursor] == [0x55, 0x48, 0x89, 0xe5] {
                return Some(UnwindRuleX86_64::UseFramePointer);
            }
        }
        if cursor >= 1 {
            // Detect push rXX with optional prefix
            let byte = slice_from_start[cursor - 1];
            if (0x50..=0x57).contains(&byte) {
                sp_offset_by_8 += 1;
                cursor -= 1;

                // Consume prefix, if present
                if cursor >= 1 && slice_from_start[cursor - 1] & 0xfe == 0x40 {
                    cursor -= 1;
                }

                continue;
            }
        }
        break;
    }
    sp_offset_by_8 += 1; // Add one for popping the return address.
    Some(UnwindRuleX86_64::OffsetSp { sp_offset_by_8 })
}

fn is_next_instruction_expected_in_prologue(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }

    // Detect push rXX
    if (0x50..=0x57).contains(&bytes[0]) {
        return true;
    }
    // Detect push rXX with prefix
    if bytes[0] & 0xfe == 0x40 && (0x50..=0x57).contains(&bytes[1]) {
        return true;
    }
    // Detect sub rsp, 0xXX
    if bytes[0..2] == [0x83, 0xec] {
        return true;
    }
    // Detect sub rsp, 0xXX with prefix
    if bytes[0..3] == [0x48, 0x83, 0xec] {
        return true;
    }
    // Detect mov rbp, rsp [0x48 0x89 0xe5]
    if bytes[0..3] == [0x48, 0x89, 0xe5] {
        return true;
    }

    false
}
