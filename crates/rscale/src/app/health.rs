use std::time::Instant;

use serde::Serialize;

use crate::config::AppConfig;
use crate::{SERVICE_NAME, VERSION};

#[derive(Debug, Clone)]
pub struct HealthService {
    started_at: Instant,
    config: AppConfig,
}

impl HealthService {
    pub fn new(config: AppConfig) -> Self {
        Self {
            started_at: Instant::now(),
            config,
        }
    }

    pub fn livez(&self) -> LivezResponse {
        LivezResponse {
            service: SERVICE_NAME,
            version: VERSION,
            status: "ok",
        }
    }

    pub fn readyz(&self, database_ready: bool) -> ReadyzResponse {
        ReadyzResponse {
            ready: database_ready,
            database_configured: self.config.database.url.is_some(),
            admin_auth_configured: self.config.auth.break_glass_token.is_some(),
            database_ready,
            oidc_enabled: self.config.auth.oidc.enabled,
        }
    }

    pub fn admin(&self, database_ready: bool, config_has_warnings: bool) -> AdminHealthResponse {
        AdminHealthResponse {
            service: SERVICE_NAME,
            version: VERSION,
            uptime_seconds: self.started_at.elapsed().as_secs(),
            bind_addr: self.config.server.bind_addr.clone(),
            database_configured: self.config.database.url.is_some(),
            admin_auth_configured: self.config.auth.break_glass_token.is_some(),
            database_ready,
            oidc_enabled: self.config.auth.oidc.enabled,
            config_has_warnings,
            log_format: self.config.telemetry.format.as_str().to_string(),
            log_timezone: self.config.telemetry.timezone.as_str().to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LivezResponse {
    pub service: &'static str,
    pub version: &'static str,
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReadyzResponse {
    pub ready: bool,
    pub database_configured: bool,
    pub admin_auth_configured: bool,
    pub database_ready: bool,
    pub oidc_enabled: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AdminHealthResponse {
    pub service: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub bind_addr: String,
    pub database_configured: bool,
    pub admin_auth_configured: bool,
    pub database_ready: bool,
    pub oidc_enabled: bool,
    pub config_has_warnings: bool,
    pub log_format: String,
    pub log_timezone: String,
}
