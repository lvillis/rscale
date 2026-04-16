use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Principal {
    pub id: u64,
    pub provider: String,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub login_name: String,
    pub display_name: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub created_at_unix_secs: u64,
}
