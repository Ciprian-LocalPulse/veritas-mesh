use thiserror::Error;

#[derive(Debug, Error)]
pub enum VeritasError {
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("signature verification failed")]
    InvalidSignature,

    #[error("proof verification failed: {0}")]
    InvalidProof(String),

    #[error("commitment opening did not match commitment")]
    CommitmentMismatch,

    #[error("rule '{0}' was not satisfied by the supplied inputs")]
    RuleViolation(String),

    #[error("unknown rule id: {0}")]
    UnknownRule(String),

    #[error("malformed key material: {0}")]
    KeyMaterial(String),
}

pub type Result<T> = std::result::Result<T, VeritasError>;
