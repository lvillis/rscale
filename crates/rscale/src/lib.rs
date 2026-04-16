pub mod app;
pub mod cli;
pub mod config;
pub mod domain;
pub mod error;
pub mod infra;
pub mod protocol;
pub mod server;

pub use error::{AppError, AppResult};

pub const SERVICE_NAME: &str = env!("CARGO_PKG_NAME");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
