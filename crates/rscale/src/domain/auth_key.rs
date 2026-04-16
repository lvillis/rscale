use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthKey {
    pub id: String,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub reusable: bool,
    pub ephemeral: bool,
    pub expires_at_unix_secs: Option<u64>,
    pub created_at_unix_secs: u64,
    pub last_used_at_unix_secs: Option<u64>,
    pub revoked_at_unix_secs: Option<u64>,
    pub usage_count: u64,
    pub state: AuthKeyState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedAuthKey {
    pub auth_key: AuthKey,
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthKeyState {
    Active,
    Revoked,
    Expired,
}

impl AuthKeyState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_key_state_round_trips_to_strings() {
        for (state, expected) in [
            (AuthKeyState::Active, "active"),
            (AuthKeyState::Revoked, "revoked"),
            (AuthKeyState::Expired, "expired"),
        ] {
            assert_eq!(state.as_str(), expected);
            assert_eq!(AuthKeyState::parse(expected), Some(state));
        }
        assert_eq!(AuthKeyState::parse("unknown"), None);
    }
}
