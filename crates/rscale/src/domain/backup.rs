use serde::{Deserialize, Serialize};

use crate::domain::{AclPolicy, AuditEvent, AuthKey, DnsConfig, Node, Principal, Route};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupAuthKey {
    pub auth_key: AuthKey,
    pub secret_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupSnapshot {
    pub format_version: u32,
    pub generated_at_unix_secs: u64,
    #[serde(default)]
    pub principals: Vec<Principal>,
    pub nodes: Vec<Node>,
    pub auth_keys: Vec<BackupAuthKey>,
    pub policy: AclPolicy,
    pub dns: DnsConfig,
    #[serde(default)]
    pub routes: Vec<Route>,
    pub audit_events: Vec<AuditEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupRestoreResult {
    pub restored_principals: u64,
    pub restored_nodes: u64,
    pub restored_auth_keys: u64,
    pub restored_routes: u64,
    pub restored_audit_events: u64,
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;
    use crate::domain::{
        AuditActor, AuditEventKind, AuthKeyState, NodeStatus, NodeTagSource, RouteApproval,
    };

    #[test]
    fn backup_snapshot_defaults_missing_optional_arrays() -> Result<(), Box<dyn Error>> {
        let snapshot: BackupSnapshot = serde_json::from_value(serde_json::json!({
            "format_version": 1,
            "generated_at_unix_secs": 1700000000u64,
            "nodes": [],
            "auth_keys": [],
            "policy": {"groups": [], "rules": []},
            "dns": {"magic_dns": false, "base_domain": null, "nameservers": [], "search_domains": []},
            "audit_events": []
        }))?;

        assert!(snapshot.principals.is_empty());
        assert!(snapshot.routes.is_empty());
        Ok(())
    }

    #[test]
    fn backup_snapshot_round_trips_with_all_sections() -> Result<(), Box<dyn Error>> {
        let snapshot = BackupSnapshot {
            format_version: 1,
            generated_at_unix_secs: 1_700_000_000,
            principals: vec![Principal {
                id: 1,
                provider: "oidc".to_string(),
                issuer: Some("https://issuer.example.com".to_string()),
                subject: Some("subject-1".to_string()),
                login_name: "alice@example.com".to_string(),
                display_name: "Alice".to_string(),
                email: Some("alice@example.com".to_string()),
                groups: vec!["group:eng".to_string()],
                created_at_unix_secs: 1_700_000_000,
            }],
            nodes: vec![Node {
                id: 10,
                stable_id: "stable-10".to_string(),
                name: "node-10".to_string(),
                hostname: "node-10.example.com".to_string(),
                auth_key_id: Some("ak-1".to_string()),
                principal_id: Some(1),
                ipv4: Some("100.64.0.10".to_string()),
                ipv6: Some("fd7a:115c:a1e0::10".to_string()),
                status: NodeStatus::Online,
                tags: vec!["tag:prod".to_string()],
                tag_source: NodeTagSource::AuthKey,
                last_seen_unix_secs: Some(1_700_000_100),
            }],
            auth_keys: vec![BackupAuthKey {
                auth_key: AuthKey {
                    id: "ak-1".to_string(),
                    description: Some("builder".to_string()),
                    tags: vec!["tag:prod".to_string()],
                    reusable: true,
                    ephemeral: false,
                    expires_at_unix_secs: None,
                    created_at_unix_secs: 1_700_000_000,
                    last_used_at_unix_secs: Some(1_700_000_050),
                    revoked_at_unix_secs: None,
                    usage_count: 1,
                    state: AuthKeyState::Active,
                },
                secret_hash: "deadbeef".to_string(),
            }],
            policy: AclPolicy::default(),
            dns: DnsConfig {
                magic_dns: true,
                base_domain: Some("tailnet.example.com".to_string()),
                nameservers: vec!["1.1.1.1".to_string()],
                search_domains: vec!["svc.tailnet.example.com".to_string()],
            },
            routes: vec![Route {
                id: 100,
                node_id: 10,
                prefix: "10.0.0.0/24".to_string(),
                advertised: true,
                approval: RouteApproval::Approved,
                approved_by_policy: true,
                is_exit_node: false,
            }],
            audit_events: vec![AuditEvent {
                id: "evt-1".to_string(),
                actor: AuditActor {
                    subject: "admin".to_string(),
                    mechanism: "break_glass_token".to_string(),
                },
                kind: AuditEventKind::BackupRestored,
                target: "backup/full".to_string(),
                occurred_at_unix_secs: 1_700_000_200,
            }],
        };

        let encoded = serde_json::to_vec(&snapshot)?;
        let decoded: BackupSnapshot = serde_json::from_slice(&encoded)?;
        assert_eq!(decoded, snapshot);
        Ok(())
    }
}
