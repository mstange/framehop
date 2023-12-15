use super::unwindregs::Reg;
use arrayvec::ArrayVec;

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

pub fn decode(encoded_ordering: u16) -> ArrayVec<Reg, 8> {
    let mut regs: ArrayVec<Reg, 8> = ENCODE_REGISTERS.into();
    let mut r = encoded_ordering;
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

pub fn encode(registers: &[Reg]) -> Option<u16> {
    if registers.len() > ENCODE_REGISTERS.len() {
        return None;
    }

    let mut r: u16 = 0;
    let mut reg_order: ArrayVec<Reg, 8> = ENCODE_REGISTERS.into();

    let mut scale: u16 = 1;
    for (i, reg) in registers.iter().enumerate() {
        let index = reg_order[i..].iter().position(|r| r == reg)?;
        if index as u16 != 0 {
            reg_order[i..].swap(index, 0);
        }
        r += index as u16 * scale;
        scale *= 8 - i as u16;
    }
    Some(r)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn register_compression() {
        use super::Reg::*;

        assert_eq!(encode(&[RAX]), None, "RAX is a volatile register, i.e. not a callee-save register, so it does not need to be restored during epilogs and is not covered by the encoding.");
        assert_eq!(encode(&[RSI, RSI]), None, "Valid register orderings only contain each register (at most) once, so there is no encoding for a sequence with repeated registers.");
        assert_eq!(
            decode(encode(&[RSI, R12, R15, R14, RBX]).unwrap()).as_slice(),
            &[RSI, R12, R15, R14, RBX],
            "This particular register ordering should roundtrip successfully"
        );
    }
}
