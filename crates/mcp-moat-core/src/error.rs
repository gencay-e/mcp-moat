use thiserror::Error;

#[derive(Error, Debug)]
pub enum MoatError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Path outside boundary: path '{attempted}' is not within sandbox root '{allowed}'")]
    PathBoundaryViolation { attempted: String, allowed: String },

    #[error("Blocked command execution: {0}")]
    BlockedCommand(String),

    #[error("DLP rule triggered: sensitive secret pattern detected ({0})")]
    DlpLeakDetected(String),

    #[error("Action rejected by operator")]
    UserRejected,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, MoatError>;
