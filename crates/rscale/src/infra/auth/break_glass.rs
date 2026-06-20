use graviola::hashing::{Hash, HashOutput, Sha256};

use crate::config::AuthConfig;
use crate::domain::AuditActor;
use crate::error::{AppError, AppResult};

#[derive(Debug, Clone)]
pub struct BreakGlassAuth {
    pub username: String,
    token_hash: HashOutput,
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
            token_hash: hash_token(&token),
        })
    }

    pub fn authenticate_bearer(&self, bearer_token: &str) -> AppResult<AuditActor> {
        let bearer_hash = hash_token(bearer_token);
        if !self.token_hash.ct_equal(bearer_hash.as_ref()) {
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

fn hash_token(token: &str) -> HashOutput {
    Sha256::hash(token.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_config(token: &str) -> AuthConfig {
        AuthConfig {
            break_glass_username: "admin@example.com".to_string(),
            break_glass_token: Some(token.to_string()),
            oidc: crate::config::OidcConfig::default(),
        }
    }

    #[test]
    fn break_glass_auth_accepts_matching_token() {
        let auth = BreakGlassAuth::from_config(&auth_config("0123456789abcdef01234567"))
            .expect("valid break-glass auth config");

        let actor = auth
            .authenticate_bearer("0123456789abcdef01234567")
            .expect("matching token should authenticate");

        assert_eq!(actor.subject, "admin@example.com");
        assert_eq!(actor.mechanism, "break_glass_token");
    }

    #[test]
    fn break_glass_auth_rejects_non_matching_token() {
        let auth = BreakGlassAuth::from_config(&auth_config("0123456789abcdef01234567"))
            .expect("valid break-glass auth config");

        let error = auth
            .authenticate_bearer("0123456789abcdef01234568")
            .expect_err("non-matching token must be rejected");

        assert_eq!(
            error.to_string(),
            "invalid request: invalid administrator token"
        );
    }

    #[test]
    fn break_glass_auth_debug_output_does_not_include_plaintext_token() {
        let auth = BreakGlassAuth::from_config(&auth_config("0123456789abcdef01234567"))
            .expect("valid break-glass auth config");

        assert!(!format!("{auth:?}").contains("0123456789abcdef01234567"));
    }
}
