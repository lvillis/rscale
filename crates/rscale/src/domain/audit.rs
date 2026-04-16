use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: String,
    pub actor: AuditActor,
    pub kind: AuditEventKind,
    pub target: String,
    pub occurred_at_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditActor {
    pub subject: String,
    pub mechanism: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    NodeRegistered,
    NodeUpdated,
    NodeDisabled,
    NodeDeleted,
    AuthKeyCreated,
    AuthKeyRevoked,
    PolicyUpdated,
    DnsUpdated,
    RouteCreated,
    RouteApproved,
    RouteRejected,
    AdminAuthenticated,
    BackupRestored,
    SshCheckApproved,
    SshCheckRejected,
}

impl AuditEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NodeRegistered => "node_registered",
            Self::NodeUpdated => "node_updated",
            Self::NodeDisabled => "node_disabled",
            Self::NodeDeleted => "node_deleted",
            Self::AuthKeyCreated => "auth_key_created",
            Self::AuthKeyRevoked => "auth_key_revoked",
            Self::PolicyUpdated => "policy_updated",
            Self::DnsUpdated => "dns_updated",
            Self::RouteCreated => "route_created",
            Self::RouteApproved => "route_approved",
            Self::RouteRejected => "route_rejected",
            Self::AdminAuthenticated => "admin_authenticated",
            Self::BackupRestored => "backup_restored",
            Self::SshCheckApproved => "ssh_check_approved",
            Self::SshCheckRejected => "ssh_check_rejected",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "node_registered" => Some(Self::NodeRegistered),
            "node_updated" => Some(Self::NodeUpdated),
            "node_disabled" => Some(Self::NodeDisabled),
            "node_deleted" => Some(Self::NodeDeleted),
            "auth_key_created" => Some(Self::AuthKeyCreated),
            "auth_key_revoked" => Some(Self::AuthKeyRevoked),
            "policy_updated" => Some(Self::PolicyUpdated),
            "dns_updated" => Some(Self::DnsUpdated),
            "route_created" => Some(Self::RouteCreated),
            "route_approved" => Some(Self::RouteApproved),
            "route_rejected" => Some(Self::RouteRejected),
            "admin_authenticated" => Some(Self::AdminAuthenticated),
            "backup_restored" => Some(Self::BackupRestored),
            "ssh_check_approved" => Some(Self::SshCheckApproved),
            "ssh_check_rejected" => Some(Self::SshCheckRejected),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_kind_round_trips_to_strings() {
        let kinds = [
            AuditEventKind::NodeRegistered,
            AuditEventKind::NodeUpdated,
            AuditEventKind::NodeDisabled,
            AuditEventKind::NodeDeleted,
            AuditEventKind::AuthKeyCreated,
            AuditEventKind::AuthKeyRevoked,
            AuditEventKind::PolicyUpdated,
            AuditEventKind::DnsUpdated,
            AuditEventKind::RouteCreated,
            AuditEventKind::RouteApproved,
            AuditEventKind::RouteRejected,
            AuditEventKind::AdminAuthenticated,
            AuditEventKind::BackupRestored,
            AuditEventKind::SshCheckApproved,
            AuditEventKind::SshCheckRejected,
        ];

        for kind in kinds {
            let encoded = kind.as_str();
            assert_eq!(AuditEventKind::parse(encoded), Some(kind));
        }
        assert_eq!(AuditEventKind::parse("unknown"), None);
    }
}
