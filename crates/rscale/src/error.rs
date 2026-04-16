use std::io;

use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("configuration error: {0}")]
    Config(#[from] tier::ConfigError),

    #[error("failed to encode JSON output: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTTP client error: {0}")]
    Http(#[from] reqx::Error),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("invalid config: {0}")]
    InvalidConfig(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("bootstrap error: {0}")]
    Bootstrap(String),
}
