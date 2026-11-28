use core::fmt::Debug;

use super::unwindregs::{UnwindRegsAarch64, ValExpressionValue, MAX_VAL_EXPRESSIONS};

/// A `DW_CFA_val_expression` rule of the form `[DW_OP_const4u <tag>; DW_OP_drop;]
/// DW_OP_breg<N> <offset>` (or `DW_OP_bregx <N> <offset>`): the value of `register`
/// is the value of register N plus `offset`, labelled with an optional 32-bit tag.
///
/// The tag doesn't change the value; DWARF consumers which don't know it ignore it.
/// Producers use it to say what the value means, for example Android's ART runtime
/// marks the dex pc of interpreter frames with the tag "DEX1".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValExpressionRuleAarch64 {
    /// The DWARF register number which the rule is for.
    pub register: u16,
    /// The constant which the expression pushes and drops before computing the value.
    pub tag: Option<u32>,
    /// The DWARF register number of the register which the value is based on.
    pub source: u16,
    /// The offset to add to the source register.
    pub offset: i64,
}

impl ValExpressionRuleAarch64 {
    /// Evaluate the rule with the register values of the frame which the rule belongs
    /// to. Returns `None` if the source register's value is unknown.
    #[inline]
    pub fn evaluate(&self, regs: &UnwindRegsAarch64) -> Option<ValExpressionValue> {
        let value = regs.get_reg(self.source)?.checked_add_signed(self.offset)?;
        Some(ValExpressionValue {
            register: self.register,
            tag: self.tag,
            value,
        })
    }
}

/// The val_expression rules of a CFI row, in the order in which the row lists them,
/// with the empty slots last.
pub type ValExpressionRulesAarch64 = [Option<ValExpressionRuleAarch64>; MAX_VAL_EXPRESSIONS];

/// The number of distinct val_expression rule lists a [`RuleTableAarch64`] can hold.
/// Cached rules refer to them with 4 bits, and 0 means "none". A Firefox process on
/// Android needs three: ART's dex pc in two different registers, and the shadow call
/// stack pointer.
const LIST_CAPACITY: usize = 15;

/// A table of the distinct val_expression rule lists which cached rules refer to by
/// index. The lists contain no addresses, so lists from all modules share the table.
///
/// The table has a fixed capacity, so interning never allocates. When it is full,
/// rows with new lists can't be cached, and their CFI rows are evaluated directly.
pub struct RuleTableAarch64 {
    lists: [ValExpressionRulesAarch64; LIST_CAPACITY],
    len: usize,
}

impl RuleTableAarch64 {
    /// Returns the index of `list`, adding it if necessary: 0 for an empty list,
    /// otherwise 1 to 15. Returns `None` if the table is full.
    pub(crate) fn intern(&mut self, list: &ValExpressionRulesAarch64) -> Option<u8> {
        if list.iter().all(Option::is_none) {
            return Some(0);
        }
        if let Some(i) = self.lists[..self.len].iter().position(|l| l == list) {
            return Some(i as u8 + 1);
        }
        if self.len == LIST_CAPACITY {
            return None;
        }
        self.lists[self.len] = *list;
        self.len += 1;
        Some(self.len as u8)
    }

    /// The list for an index which [`intern`](Self::intern) returned, other than 0.
    #[inline]
    pub(crate) fn get(&self, index: u8) -> &ValExpressionRulesAarch64 {
        &self.lists[usize::from(index) - 1]
    }

    /// The number of lists in the table.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for RuleTableAarch64 {
    fn default() -> Self {
        Self {
            lists: [[None; MAX_VAL_EXPRESSIONS]; LIST_CAPACITY],
            len: 0,
        }
    }
}

impl Debug for RuleTableAarch64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(&self.lists[..self.len]).finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn list(source: u16) -> ValExpressionRulesAarch64 {
        [
            Some(ValExpressionRuleAarch64 {
                register: 0,
                tag: Some(0x31584544),
                source,
                offset: 0,
            }),
            None,
        ]
    }

    #[test]
    fn test_intern() {
        let mut table = RuleTableAarch64::default();
        assert_eq!(table.intern(&[None; MAX_VAL_EXPRESSIONS]), Some(0));
        assert!(table.is_empty());
        assert_eq!(table.intern(&list(22)), Some(1));
        assert_eq!(table.intern(&list(19)), Some(2));
        assert_eq!(table.intern(&list(22)), Some(1));
        assert_eq!(table.get(2), &list(19));
        assert_eq!(table.len(), 2);
        for source in 0..13 {
            assert_eq!(table.intern(&list(100 + source)), Some(3 + source as u8));
        }
        assert_eq!(table.intern(&list(200)), None);
        // Lists which are already in the table can still be found.
        assert_eq!(table.intern(&list(19)), Some(2));
        assert_eq!(table.len(), LIST_CAPACITY);
    }
}
