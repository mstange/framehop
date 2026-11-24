#[derive(Debug, Clone)]
pub enum UnwindResult<R> {
    ExecRule(R),
    /// Execute the rule without caching it for the address.
    ExecRuleUncached(R),
    Uncacheable(u64),
    /// Like `Uncacheable`, but the frame was a signal trampoline: the address is where its
    /// caller was interrupted, not a return address.
    Interrupted(u64),
}
