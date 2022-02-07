pub enum UnwindResult<R> {
    ExecRule(R),
    Uncacheable(u64),
}
