use crate::config::AuthConfig;
use crate::domain::AuditActor;
use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakGlassAuth {
    pub username: String,
    token: String,
}

impl BreakGlassAuth {
    pub fn from_config(config: &AuthConfig) -> AppResult<Self> {
        let token = config.break_glass_token.clone().ok_or_else(|| {
            AppError::InvalidConfig("auth.break_glass_token is required".to_string())
        })?;

        if token.trim().is_empty() {
            return Err(AppError::InvalidConfig(
                "auth.break_glass_token must not be empty".to_string(),
            ));
        }

        Ok(Self {
            username: config.break_glass_username.clone(),
            token,
        })
    }

    pub fn authenticate_bearer(&self, bearer_token: &str) -> AppResult<AuditActor> {
        if bearer_token != self.token {
            return Err(AppError::InvalidRequest(
                "invalid administrator token".to_string(),
            ));
        }

        Ok(self.actor())
    }

    pub fn actor(&self) -> AuditActor {
        AuditActor {
            subject: self.username.clone(),
            mechanism: "break_glass_token".to_string(),
        }
    }
}
