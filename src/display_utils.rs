use core::fmt::{Debug, LowerHex};

pub struct HexNum<N: LowerHex>(pub N);

impl<N: LowerHex> Debug for HexNum<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}
