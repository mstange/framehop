use crate::error::Error;

pub trait UnwindRule: Copy + core::fmt::Debug {
    type UnwindRegs;

    /// Storage for the parts of cached rules which don't fit into the rules. It
    /// lives in the [`Cache`](crate::cache::Cache) and is allocated with it, so
    /// unwinding doesn't need to allocate.
    type RuleTable: Default;

    fn exec<F>(
        self,
        table: &Self::RuleTable,
        is_first_frame: bool,
        regs: &mut Self::UnwindRegs,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>;

    fn rule_for_stub_functions() -> Self;
    fn rule_for_function_start() -> Self;
    fn fallback_rule() -> Self;
}
