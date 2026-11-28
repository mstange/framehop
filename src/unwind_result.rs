#[derive(Debug, Clone)]
pub enum UnwindResult<R> {
    ExecRule(R),
    Uncacheable(u64),
    /// The step failed because of the current register values, not because of the
    /// unwind information alone, so nothing is cached for this address.
    UncacheableError(crate::Error),
}
