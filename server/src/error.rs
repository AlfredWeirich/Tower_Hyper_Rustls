#[derive(Debug, thiserror::Error)]
pub enum SrvError {
    #[error("Infallible: {0}")]
    Infallible(#[from] std::convert::Infallible),
    #[error("Hyper: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("HyperUtil: {0}")]
    HyperUtil(#[from] hyper_util::client::legacy::Error),
    // ... any other variants
}
