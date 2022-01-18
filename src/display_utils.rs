use std::fmt::{LowerHex, Binary, Debug, Display};

pub struct HexNum<N: LowerHex>(pub N);

impl<N: LowerHex> Debug for HexNum<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}

pub struct BinNum<N: Binary>(pub N);

impl<N: Binary> Debug for BinNum<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Binary::fmt(&self.0, f)
    }
}
pub struct RelativeOffset(pub i32);

impl Display for RelativeOffset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 != 0 {
            if self.0 > 0 {
                f.write_str("+")?;
            }
            Display::fmt(&self.0, f)?;
        }
        Ok(())
    }
}
