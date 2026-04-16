use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    pub id: u64,
    pub stable_id: String,
    pub name: String,
    pub hostname: String,
    pub auth_key_id: Option<String>,
    pub principal_id: Option<u64>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub status: NodeStatus,
    pub tags: Vec<String>,
    #[serde(default)]
    pub tag_source: NodeTagSource,
    pub last_seen_unix_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Pending,
    Online,
    Offline,
    Expired,
    Disabled,
}

impl NodeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Online => "online",
            Self::Offline => "offline",
            Self::Expired => "expired",
            Self::Disabled => "disabled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "online" => Some(Self::Online),
            "offline" => Some(Self::Offline),
            "expired" => Some(Self::Expired),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NodeTagSource {
    #[default]
    None,
    Request,
    AuthKey,
    Admin,
}

impl NodeTagSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Request => "request",
            Self::AuthKey => "auth_key",
            Self::Admin => "admin",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "request" => Some(Self::Request),
            "auth_key" => Some(Self::AuthKey),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    pub fn is_server_forced(self) -> bool {
        matches!(self, Self::AuthKey | Self::Admin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_status_round_trips_to_strings() {
        for (status, expected) in [
            (NodeStatus::Pending, "pending"),
            (NodeStatus::Online, "online"),
            (NodeStatus::Offline, "offline"),
            (NodeStatus::Expired, "expired"),
            (NodeStatus::Disabled, "disabled"),
        ] {
            assert_eq!(status.as_str(), expected);
            assert_eq!(NodeStatus::parse(expected), Some(status));
        }
        assert_eq!(NodeStatus::parse("unknown"), None);
    }

    #[test]
    fn node_tag_source_round_trips_and_marks_server_forced_sources() {
        for (source, expected, is_server_forced) in [
            (NodeTagSource::None, "none", false),
            (NodeTagSource::Request, "request", false),
            (NodeTagSource::AuthKey, "auth_key", true),
            (NodeTagSource::Admin, "admin", true),
        ] {
            assert_eq!(source.as_str(), expected);
            assert_eq!(NodeTagSource::parse(expected), Some(source));
            assert_eq!(source.is_server_forced(), is_server_forced);
        }
        assert_eq!(NodeTagSource::parse("unknown"), None);
    }
}
