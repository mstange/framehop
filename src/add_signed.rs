/// Add a signed integer to this unsigned integer, with wrapping.
#[allow(unused)]
pub fn wrapping_add_signed<T: AddSigned>(lhs: T, rhs: T::Signed) -> T {
    lhs.wrapping_add_signed(rhs)
}

/// Add a signed integer to this unsigned integer, but only if doing so
/// does not cause underflow / overflow.
pub fn checked_add_signed<T: AddSigned>(lhs: T, rhs: T::Signed) -> Option<T> {
    lhs.checked_add_signed(rhs)
}

/// A trait which adds method to unsigned integers which allow checked and
/// wrapping addition of the corresponding signed integer type.
/// Unfortunately, these methods conflict with the proposed standard rust
/// methods, so this trait isn't actually usable without risking build
/// errors once these methods are stabilized.
/// https://github.com/rust-lang/rust/issues/87840
pub trait AddSigned: Sized {
    type Signed;

    /// Add a signed integer to this unsigned integer, with wrapping.
    fn wrapping_add_signed(self, rhs: Self::Signed) -> Self;

    /// Add a signed integer to this unsigned integer, but only if doing so
    /// does not cause underflow / overflow.
    fn checked_add_signed(self, rhs: Self::Signed) -> Option<Self>;
}

impl AddSigned for u64 {
    type Signed = i64;

    fn wrapping_add_signed(self, rhs: i64) -> u64 {
        self.wrapping_add(rhs as u64)
    }

    fn checked_add_signed(self, rhs: i64) -> Option<u64> {
        let res = AddSigned::wrapping_add_signed(self, rhs);
        if (rhs >= 0 && res >= self) || (rhs < 0 && res < self) {
            Some(res)
        } else {
            None
        }
    }
}

impl AddSigned for u32 {
    type Signed = i32;

    fn wrapping_add_signed(self, rhs: i32) -> u32 {
        self.wrapping_add(rhs as u32)
    }

    fn checked_add_signed(self, rhs: i32) -> Option<u32> {
        let res = AddSigned::wrapping_add_signed(self, rhs);
        if (rhs >= 0 && res >= self) || (rhs < 0 && res < self) {
            Some(res)
        } else {
            None
        }
    }
}
