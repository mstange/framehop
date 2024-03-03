use crate::FrameAddress;

#[derive(Debug, Clone)]
pub enum UnwindResult<R> {
    ExecRule(R),
    Uncacheable(Option<FrameAddress>),
}
