use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use graviola::random;
use serde_json::Value;
use sqlx::Row;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::domain::{
    AclPolicy, AuditActor, AuditEventKind, AuthKeyState, Node, NodeStatus, NodeTagSource,
    Principal, Route, RouteApproval, normalize_acl_tags, validate_route_prefix,
};
use crate::error::{AppError, AppResult};
use crate::infra::auth::oidc::OidcPrincipal;
use crate::protocol::{MapRequest, RegisterRequest, RegisterResponseAuth};

use super::postgres::{InsertNode, PostgresStore};

#[derive(Debug, Clone)]
pub struct ControlNodeRecord {
    pub node: Node,
    pub principal: Option<Principal>,
    pub machine_key: String,
    pub node_key: String,
    pub disco_key: String,
    pub hostinfo: Option<Value>,
    pub endpoints: Vec<String>,
    pub key_expiry_unix_secs: Option<u64>,
    pub map_request_version: u32,
    pub session_expires_at_unix_secs: Option<u64>,
    pub created_at_unix_secs: u64,
}

#[derive(Debug, Clone)]
pub struct PendingOidcAuthRequest {
    pub auth_id: String,
    pub machine_key: String,
    pub node_key: String,
    pub oidc_state: String,
    pub oidc_nonce: String,
    pub pkce_verifier: String,
    pub principal_issuer: Option<String>,
    pub principal_sub: Option<String>,
    pub principal_email: Option<String>,
    pub principal_name: Option<String>,
    pub principal_groups: Vec<String>,
    pub node_id: Option<u64>,
    pub expires_at_unix_secs: u64,
    pub completed_at_unix_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshAuthRequestStatus {
    Pending,
    Approved,
    Rejected,
}

impl SshAuthRequestStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    fn parse(value: &str) -> AppResult<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            _ => Err(AppError::Bootstrap(format!(
                "unsupported ssh auth request status in database: {value}",
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingSshAuthRequest {
    pub auth_id: String,
    pub src_node_id: u64,
    pub dst_node_id: u64,
    pub ssh_user: String,
    pub local_user: String,
    pub oidc_state: String,
    pub oidc_nonce: String,
    pub pkce_verifier: String,
    pub status: SshAuthRequestStatus,
    pub message: Option<String>,
    pub principal_issuer: Option<String>,
    pub principal_sub: Option<String>,
    pub principal_email: Option<String>,
    pub principal_name: Option<String>,
    pub expires_at_unix_secs: u64,
    pub resolved_at_unix_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AdvertisedRoute {
    prefix: String,
    is_exit_node: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlannedAdvertisedRouteChange {
    existing_id: Option<u64>,
    prefix: String,
    advertised: bool,
    approval: RouteApproval,
    approved_by_policy: bool,
    is_exit_node: bool,
    auto_approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestedTagAssignment {
    tags: Vec<String>,
    principal_id: Option<u64>,
    tag_source: NodeTagSource,
}

impl PostgresStore {
    pub async fn register_control_node(
        &self,
        machine_key: &str,
        request: &RegisterRequest,
    ) -> AppResult<ControlNodeRecord> {
        validate_control_machine_key(machine_key)?;
        validate_register_request(request)?;

        let hostinfo = request
            .hostinfo
            .clone()
            .unwrap_or(Value::Object(Default::default()));
        let key_expiry_unix_secs = parse_rfc3339_unix_secs(&request.expiry)?;
        let now_unix_secs = now_unix_secs()?;
        let actor = AuditActor {
            subject: format!("machine:{machine_key}"),
            mechanism: "ts2021".to_string(),
        };
        let mut tx = self.pool.begin().await?;

        let existing = sqlx::query(
            r#"
            SELECT node_id, node_key
            FROM node_control_state
            WHERE machine_key = $1
            FOR UPDATE
            "#,
        )
        .bind(machine_key)
        .fetch_optional(&mut *tx)
        .await?;

        let node_id = if let Some(existing) = existing {
            let node_id = i64_to_u64(existing.get::<i64, _>("node_id"))?;
            let current_node_key = existing.get::<String, _>("node_key");
            if !request.old_node_key.is_empty()
                && request.old_node_key != current_node_key
                && request.node_key != current_node_key
            {
                return Err(AppError::Unauthorized(
                    "old node key does not match the registered machine".to_string(),
                ));
            }

            sqlx::query(
                r#"
                UPDATE node_control_state
                SET
                    node_key = $2,
                    hostinfo = $3,
                    key_expiry = to_timestamp($4),
                    map_request_version = $5,
                    last_control_seen_at = now(),
                    updated_at = now()
                WHERE node_id = $1
                "#,
            )
            .bind(u64_to_i64(node_id)?)
            .bind(&request.node_key)
            .bind(hostinfo.clone())
            .bind(key_expiry_unix_secs.map(|value| value as f64))
            .bind(i64::from(request.version))
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                r#"
                UPDATE nodes
                SET
                    status = $2,
                    last_seen_unix_secs = $3,
                    updated_at = now()
                WHERE id = $1
                "#,
            )
            .bind(u64_to_i64(node_id)?)
            .bind(NodeStatus::Online.as_str())
            .bind(u64_to_i64(now_unix_secs)?)
            .execute(&mut *tx)
            .await?;

            let node = load_node_tx(&mut tx, node_id).await?;
            let request_tags = parse_request_tags(&hostinfo)?;
            if node.tag_source.is_server_forced() {
                if hostinfo_has_explicit_request_tags(&hostinfo) && request_tags != node.tags {
                    return Err(server_tag_update_not_permitted_error());
                }
            } else if !request_tags.is_empty() {
                return Err(requested_tags_not_permitted_error(&request_tags));
            }
            let principal = self.load_route_principal(node.principal_id).await?;
            self.sync_advertised_routes_tx(&mut tx, &node, principal.as_ref(), &hostinfo, &actor)
                .await?;

            node_id
        } else {
            let auth_key = authenticate_protocol_auth_key(request.auth.as_ref())?;
            let authenticated_auth_key = self.authenticate_auth_key(&mut tx, auth_key).await?;
            let request_tags = parse_request_tags(&hostinfo)?;
            if !request_tags.is_empty() {
                return Err(requested_tags_not_permitted_error(&request_tags));
            }
            let hostname = protocol_hostname(&hostinfo)
                .unwrap_or_else(|| fallback_protocol_hostname(machine_key));
            let name = format!("{hostname}-{}", short_machine_key(machine_key));
            let (ipv4, ipv6) = self.allocate_node_addresses(&mut tx, None, None).await?;

            let node = self
                .insert_node(
                    &mut tx,
                    InsertNode {
                        stable_id: Uuid::new_v4().to_string(),
                        name,
                        hostname,
                        auth_key_id: Some(authenticated_auth_key.id.clone()),
                        principal_id: None,
                        session_secret_hash: None,
                        session_expires_at_unix_secs: None,
                        ipv4,
                        ipv6,
                        status: NodeStatus::Online,
                        tags: authenticated_auth_key.tags.clone(),
                        tag_source: if authenticated_auth_key.tags.is_empty() {
                            NodeTagSource::None
                        } else {
                            NodeTagSource::AuthKey
                        },
                        last_seen_unix_secs: Some(now_unix_secs),
                    },
                )
                .await?;

            sqlx::query(
                r#"
                INSERT INTO node_control_state (
                    node_id,
                    machine_key,
                    node_key,
                    hostinfo,
                    endpoints,
                    key_expiry,
                    map_request_version,
                    last_control_seen_at
                )
                VALUES ($1, $2, $3, $4, '[]'::jsonb, to_timestamp($5), $6, now())
                "#,
            )
            .bind(u64_to_i64(node.id)?)
            .bind(machine_key)
            .bind(&request.node_key)
            .bind(hostinfo.clone())
            .bind(key_expiry_unix_secs.map(|value| value as f64))
            .bind(i64::from(request.version))
            .execute(&mut *tx)
            .await?;

            let update_state = if authenticated_auth_key.reusable {
                AuthKeyState::Active
            } else {
                AuthKeyState::Revoked
            };

            sqlx::query(
                r#"
                UPDATE auth_keys
                SET
                    usage_count = usage_count + 1,
                    last_used_at = now(),
                    state = $2,
                    revoked_at = CASE WHEN $2 = 'revoked' THEN now() ELSE revoked_at END
                WHERE id = $1
                "#,
            )
            .bind(&authenticated_auth_key.id)
            .bind(update_state.as_str())
            .execute(&mut *tx)
            .await?;
            self.sync_advertised_routes_tx(&mut tx, &node, None, &hostinfo, &actor)
                .await?;
            self.record_audit_event_tx(
                &mut tx,
                AuditEventKind::NodeRegistered,
                &actor,
                &format!("node/{}", node.id),
            )
            .await?;

            node.id
        };

        tx.commit().await?;
        self.notify_control_change().await;
        self.get_control_node(node_id).await
    }

    pub async fn begin_oidc_auth_request(
        &self,
        machine_key: &str,
        request: &RegisterRequest,
        ttl_secs: u64,
    ) -> AppResult<PendingOidcAuthRequest> {
        validate_control_machine_key(machine_key)?;
        validate_register_request(request)?;

        if ttl_secs == 0 {
            return Err(AppError::InvalidConfig(
                "OIDC auth_flow_ttl_secs must be greater than zero".to_string(),
            ));
        }

        let auth_id = Uuid::new_v4().to_string();
        let expires_at_unix_secs = now_unix_secs()?
            .checked_add(ttl_secs)
            .ok_or_else(|| AppError::Bootstrap("OIDC auth request expiry overflow".to_string()))?;
        let hostinfo = request
            .hostinfo
            .clone()
            .unwrap_or(Value::Object(Default::default()));
        let oidc_state = random_token(32)?;
        let oidc_nonce = random_token(32)?;
        let pkce_verifier = random_token(48)?;

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"
            UPDATE oidc_auth_requests
            SET
                expires_at = now(),
                updated_at = now()
            WHERE machine_key = $1
              AND completed_at IS NULL
              AND expires_at > now()
            "#,
        )
        .bind(machine_key)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO oidc_auth_requests (
                id,
                machine_key,
                node_key,
                old_node_key,
                nl_key,
                expiry,
                hostinfo,
                ephemeral,
                tailnet,
                oidc_state,
                oidc_nonce,
                pkce_verifier,
                expires_at
            )
            VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                to_timestamp($6),
                $7,
                $8,
                $9,
                $10,
                $11,
                $12,
                to_timestamp($13)
            )
            "#,
        )
        .bind(&auth_id)
        .bind(machine_key)
        .bind(&request.node_key)
        .bind(&request.old_node_key)
        .bind(&request.nl_key)
        .bind(parse_rfc3339_unix_secs(&request.expiry)?.map(|value| value as f64))
        .bind(hostinfo)
        .bind(request.ephemeral)
        .bind(&request.tailnet)
        .bind(&oidc_state)
        .bind(&oidc_nonce)
        .bind(&pkce_verifier)
        .bind(expires_at_unix_secs as f64)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        self.get_oidc_auth_request(&auth_id).await
    }

    pub async fn get_oidc_auth_request(&self, auth_id: &str) -> AppResult<PendingOidcAuthRequest> {
        let row = sqlx::query(oidc_auth_request_select_sql_with_where("id = $1"))
            .bind(auth_id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => map_oidc_auth_request_row(row),
            None => Err(AppError::NotFound(format!("oidc auth request {auth_id}"))),
        }
    }

    pub async fn find_oidc_auth_request_by_state(
        &self,
        state: &str,
    ) -> AppResult<PendingOidcAuthRequest> {
        let row = sqlx::query(oidc_auth_request_select_sql_with_where("oidc_state = $1"))
            .bind(state)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => map_oidc_auth_request_row(row),
            None => Err(AppError::NotFound("oidc auth request state".to_string())),
        }
    }

    pub async fn complete_oidc_auth_request(
        &self,
        auth_id: &str,
        principal: &OidcPrincipal,
    ) -> AppResult<PendingOidcAuthRequest> {
        let groups = serde_json::to_value(&principal.groups)?;
        let row = sqlx::query(
            r#"
            UPDATE oidc_auth_requests
            SET
                principal_sub = $2,
                principal_issuer = $3,
                principal_email = $4,
                principal_name = $5,
                principal_groups = $6,
                completed_at = COALESCE(completed_at, now()),
                updated_at = now()
            WHERE id = $1
              AND expires_at > now()
            RETURNING
                id,
                machine_key,
                node_key,
                oidc_state,
                oidc_nonce,
                pkce_verifier,
                principal_sub,
                principal_issuer,
                principal_email,
                principal_name,
                principal_groups,
                node_id,
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix_secs,
                EXTRACT(EPOCH FROM completed_at)::bigint AS completed_at_unix_secs
            "#,
        )
        .bind(auth_id)
        .bind(&principal.subject)
        .bind(&principal.issuer)
        .bind(principal.email.as_deref())
        .bind(principal.display_name.as_deref())
        .bind(groups)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => map_oidc_auth_request_row(row),
            None => Err(AppError::Unauthorized(
                "OIDC auth request is missing or expired".to_string(),
            )),
        }
    }

    pub async fn create_ssh_auth_request(
        &self,
        src_node_id: u64,
        dst_node_id: u64,
        ssh_user: &str,
        local_user: &str,
        ttl_secs: u64,
    ) -> AppResult<PendingSshAuthRequest> {
        let expires_at_unix_secs = now_unix_secs()?.checked_add(ttl_secs).ok_or_else(|| {
            AppError::Bootstrap("SSH auth request expiry overflowed u64".to_string())
        })?;
        let auth_id = random_token(24)?;
        let oidc_state = random_token(32)?;
        let oidc_nonce = random_token(32)?;
        let pkce_verifier = random_token(48)?;

        let mut tx = self.pool.begin().await?;
        ensure_node_exists(&mut tx, src_node_id, "ssh source node").await?;
        ensure_node_exists(&mut tx, dst_node_id, "ssh destination node").await?;

        sqlx::query(
            r#"
            INSERT INTO ssh_auth_requests (
                id,
                src_node_id,
                dst_node_id,
                ssh_user,
                local_user,
                oidc_state,
                oidc_nonce,
                pkce_verifier,
                status,
                expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, to_timestamp($10))
            "#,
        )
        .bind(&auth_id)
        .bind(u64_to_i64(src_node_id)?)
        .bind(u64_to_i64(dst_node_id)?)
        .bind(ssh_user)
        .bind(local_user)
        .bind(&oidc_state)
        .bind(&oidc_nonce)
        .bind(&pkce_verifier)
        .bind(SshAuthRequestStatus::Pending.as_str())
        .bind(expires_at_unix_secs as f64)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        self.get_ssh_auth_request(&auth_id).await
    }

    pub async fn get_ssh_auth_request(&self, auth_id: &str) -> AppResult<PendingSshAuthRequest> {
        let row = sqlx::query(ssh_auth_request_select_sql_with_where("id = $1"))
            .bind(auth_id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => map_ssh_auth_request_row(row),
            None => Err(AppError::NotFound(format!("ssh auth request {auth_id}"))),
        }
    }

    pub async fn find_ssh_auth_request_by_state(
        &self,
        state: &str,
    ) -> AppResult<PendingSshAuthRequest> {
        let row = sqlx::query(ssh_auth_request_select_sql_with_where("oidc_state = $1"))
            .bind(state)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => map_ssh_auth_request_row(row),
            None => Err(AppError::NotFound("ssh auth request state".to_string())),
        }
    }

    pub async fn approve_ssh_auth_request(
        &self,
        auth_id: &str,
        principal: &OidcPrincipal,
    ) -> AppResult<PendingSshAuthRequest> {
        let row = sqlx::query(
            r#"
            UPDATE ssh_auth_requests
            SET
                status = $2,
                message = NULL,
                principal_issuer = $3,
                principal_sub = $4,
                principal_email = $5,
                principal_name = $6,
                resolved_at = COALESCE(resolved_at, now()),
                updated_at = now()
            WHERE id = $1
              AND expires_at > now()
            RETURNING
                id,
                src_node_id,
                dst_node_id,
                ssh_user,
                local_user,
                oidc_state,
                oidc_nonce,
                pkce_verifier,
                status,
                message,
                principal_issuer,
                principal_sub,
                principal_email,
                principal_name,
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix_secs,
                EXTRACT(EPOCH FROM resolved_at)::bigint AS resolved_at_unix_secs
            "#,
        )
        .bind(auth_id)
        .bind(SshAuthRequestStatus::Approved.as_str())
        .bind(&principal.issuer)
        .bind(&principal.subject)
        .bind(principal.email.as_deref())
        .bind(principal.display_name.as_deref())
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let pending = map_ssh_auth_request_row(row)?;
                self.record_audit_event(
                    AuditEventKind::SshCheckApproved,
                    &AuditActor {
                        subject: principal
                            .email
                            .clone()
                            .unwrap_or_else(|| principal.subject.clone()),
                        mechanism: "oidc".to_string(),
                    },
                    &ssh_check_audit_target(
                        pending.src_node_id,
                        pending.dst_node_id,
                        &pending.ssh_user,
                        &pending.local_user,
                    ),
                )
                .await?;
                Ok(pending)
            }
            None => Err(AppError::Unauthorized(
                "SSH auth request is missing or expired".to_string(),
            )),
        }
    }

    pub async fn reject_ssh_auth_request(
        &self,
        auth_id: &str,
        message: &str,
    ) -> AppResult<PendingSshAuthRequest> {
        let row = sqlx::query(
            r#"
            UPDATE ssh_auth_requests
            SET
                status = $2,
                message = $3,
                resolved_at = COALESCE(resolved_at, now()),
                updated_at = now()
            WHERE id = $1
            RETURNING
                id,
                src_node_id,
                dst_node_id,
                ssh_user,
                local_user,
                oidc_state,
                oidc_nonce,
                pkce_verifier,
                status,
                message,
                principal_issuer,
                principal_sub,
                principal_email,
                principal_name,
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix_secs,
                EXTRACT(EPOCH FROM resolved_at)::bigint AS resolved_at_unix_secs
            "#,
        )
        .bind(auth_id)
        .bind(SshAuthRequestStatus::Rejected.as_str())
        .bind(message)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let pending = map_ssh_auth_request_row(row)?;
                self.record_audit_event(
                    AuditEventKind::SshCheckRejected,
                    &AuditActor {
                        subject: pending
                            .principal_email
                            .clone()
                            .or_else(|| pending.principal_sub.clone())
                            .unwrap_or_else(|| "control-plane".to_string()),
                        mechanism: pending
                            .principal_issuer
                            .as_deref()
                            .map(|_| "oidc".to_string())
                            .unwrap_or_else(|| "system".to_string()),
                    },
                    &ssh_check_audit_target(
                        pending.src_node_id,
                        pending.dst_node_id,
                        &pending.ssh_user,
                        &pending.local_user,
                    ),
                )
                .await?;
                Ok(pending)
            }
            None => Err(AppError::NotFound(format!("ssh auth request {auth_id}"))),
        }
    }

    pub async fn last_ssh_check_approval(
        &self,
        src_node_id: u64,
        dst_node_id: u64,
        ssh_user: &str,
        local_user: &str,
    ) -> AppResult<Option<u64>> {
        let approved_at = sqlx::query_scalar::<_, Option<i64>>(
            r#"
            SELECT EXTRACT(EPOCH FROM authenticated_at)::bigint
            FROM ssh_check_approvals
            WHERE src_node_id = $1
              AND dst_node_id = $2
              AND ssh_user = $3
              AND local_user = $4
            "#,
        )
        .bind(u64_to_i64(src_node_id)?)
        .bind(u64_to_i64(dst_node_id)?)
        .bind(ssh_user)
        .bind(local_user)
        .fetch_optional(&self.pool)
        .await?
        .flatten()
        .map(i64_to_u64)
        .transpose()?;

        Ok(approved_at)
    }

    pub async fn record_ssh_check_approval(
        &self,
        src_node_id: u64,
        dst_node_id: u64,
        ssh_user: &str,
        local_user: &str,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO ssh_check_approvals (
                src_node_id,
                dst_node_id,
                ssh_user,
                local_user,
                authenticated_at
            )
            VALUES ($1, $2, $3, $4, now())
            ON CONFLICT (src_node_id, dst_node_id, ssh_user, local_user)
            DO UPDATE SET authenticated_at = EXCLUDED.authenticated_at
            "#,
        )
        .bind(u64_to_i64(src_node_id)?)
        .bind(u64_to_i64(dst_node_id)?)
        .bind(ssh_user)
        .bind(local_user)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn clear_ssh_check_approvals(&self) -> AppResult<()> {
        sqlx::query("DELETE FROM ssh_check_approvals")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn register_control_node_from_oidc_auth(
        &self,
        machine_key: &str,
        auth_id: &str,
        request: &RegisterRequest,
    ) -> AppResult<ControlNodeRecord> {
        validate_control_machine_key(machine_key)?;
        validate_register_request(request)?;

        let hostinfo = request
            .hostinfo
            .clone()
            .unwrap_or(Value::Object(Default::default()));
        let key_expiry_unix_secs = parse_rfc3339_unix_secs(&request.expiry)?;
        let now_unix_secs = now_unix_secs()?;
        let actor = AuditActor {
            subject: format!("machine:{machine_key}"),
            mechanism: "oidc".to_string(),
        };
        let mut tx = self.pool.begin().await?;
        let pending = sqlx::query(
            r#"
            SELECT
                id,
                node_key,
                principal_issuer,
                principal_sub,
                principal_email,
                principal_name,
                principal_groups,
                EXTRACT(EPOCH FROM completed_at)::bigint AS completed_at_unix_secs,
                node_id
            FROM oidc_auth_requests
            WHERE id = $1
              AND machine_key = $2
              AND expires_at > now()
            FOR UPDATE
            "#,
        )
        .bind(auth_id)
        .bind(machine_key)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            AppError::Unauthorized("OIDC auth request is missing or expired".to_string())
        })?;

        if pending
            .get::<Option<i64>, _>("completed_at_unix_secs")
            .is_none()
        {
            return Err(AppError::Unauthorized(
                "OIDC authentication is still pending".to_string(),
            ));
        }

        let existing = sqlx::query(
            r#"
            SELECT node_id, node_key
            FROM node_control_state
            WHERE machine_key = $1
            FOR UPDATE
            "#,
        )
        .bind(machine_key)
        .fetch_optional(&mut *tx)
        .await?;

        let node_id = if let Some(existing) = existing {
            let node_id = i64_to_u64(existing.get::<i64, _>("node_id"))?;
            let current_node_key = existing.get::<String, _>("node_key");
            if !request.old_node_key.is_empty()
                && request.old_node_key != current_node_key
                && request.node_key != current_node_key
            {
                return Err(AppError::Unauthorized(
                    "old node key does not match the registered machine".to_string(),
                ));
            }

            sqlx::query(
                r#"
                UPDATE node_control_state
                SET
                    node_key = $2,
                    hostinfo = $3,
                    key_expiry = to_timestamp($4),
                    map_request_version = $5,
                    last_control_seen_at = now(),
                    updated_at = now()
                WHERE node_id = $1
                "#,
            )
            .bind(u64_to_i64(node_id)?)
            .bind(&request.node_key)
            .bind(hostinfo.clone())
            .bind(key_expiry_unix_secs.map(|value| value as f64))
            .bind(i64::from(request.version))
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                r#"
                UPDATE nodes
                SET
                    status = $2,
                    last_seen_unix_secs = $3,
                    updated_at = now()
                WHERE id = $1
                "#,
            )
            .bind(u64_to_i64(node_id)?)
            .bind(NodeStatus::Online.as_str())
            .bind(u64_to_i64(now_unix_secs)?)
            .execute(&mut *tx)
            .await?;

            let principal = self
                .upsert_principal_from_pending(&mut tx, &pending)
                .await?;
            let existing_node = load_node_tx(&mut tx, node_id).await?;
            let policy = load_policy_tx(&mut tx).await?;
            let requested_tags = resolve_requested_tags_for_principal(
                &policy,
                &existing_node,
                &principal,
                &hostinfo,
            )?;
            apply_requested_tag_assignment_tx(&mut tx, node_id, &requested_tags).await?;
            sqlx::query(
                r#"
                UPDATE oidc_auth_requests
                SET
                    node_id = $2,
                    updated_at = now()
                WHERE id = $1
                "#,
            )
            .bind(auth_id)
            .bind(u64_to_i64(node_id)?)
            .execute(&mut *tx)
            .await?;

            let node = load_node_tx(&mut tx, node_id).await?;
            let route_principal = self.load_route_principal(node.principal_id).await?;
            self.sync_advertised_routes_tx(
                &mut tx,
                &node,
                route_principal.as_ref(),
                &hostinfo,
                &actor,
            )
            .await?;

            node_id
        } else {
            let registered_node_id = pending
                .get::<Option<i64>, _>("node_id")
                .map(i64_to_u64)
                .transpose()?;
            if let Some(node_id) = registered_node_id {
                tx.commit().await?;
                return self.get_control_node(node_id).await;
            }

            let initial_node_key = pending.get::<String, _>("node_key");
            if request.node_key != initial_node_key {
                return Err(AppError::Unauthorized(
                    "node key does not match the approved interactive registration".to_string(),
                ));
            }

            let hostname = protocol_hostname(&hostinfo)
                .unwrap_or_else(|| fallback_protocol_hostname(machine_key));
            let name = format!("{hostname}-{}", short_machine_key(machine_key));
            let (ipv4, ipv6) = self.allocate_node_addresses(&mut tx, None, None).await?;
            let principal = self
                .upsert_principal_from_pending(&mut tx, &pending)
                .await?;
            let policy = load_policy_tx(&mut tx).await?;
            let requested_tags = resolve_requested_tags_for_principal(
                &policy,
                &Node {
                    id: 0,
                    stable_id: String::new(),
                    name: name.clone(),
                    hostname: hostname.clone(),
                    auth_key_id: None,
                    principal_id: Some(principal.id),
                    ipv4: ipv4.clone(),
                    ipv6: ipv6.clone(),
                    status: NodeStatus::Online,
                    tags: Vec::new(),
                    tag_source: NodeTagSource::None,
                    last_seen_unix_secs: Some(now_unix_secs),
                },
                &principal,
                &hostinfo,
            )?;

            let node = self
                .insert_node(
                    &mut tx,
                    InsertNode {
                        stable_id: Uuid::new_v4().to_string(),
                        name,
                        hostname,
                        auth_key_id: None,
                        principal_id: requested_tags.principal_id,
                        session_secret_hash: None,
                        session_expires_at_unix_secs: None,
                        ipv4,
                        ipv6,
                        status: NodeStatus::Online,
                        tags: requested_tags.tags,
                        tag_source: requested_tags.tag_source,
                        last_seen_unix_secs: Some(now_unix_secs),
                    },
                )
                .await?;

            sqlx::query(
                r#"
                INSERT INTO node_control_state (
                    node_id,
                    machine_key,
                    node_key,
                    hostinfo,
                    endpoints,
                    key_expiry,
                    map_request_version,
                    last_control_seen_at
                )
                VALUES ($1, $2, $3, $4, '[]'::jsonb, to_timestamp($5), $6, now())
                "#,
            )
            .bind(u64_to_i64(node.id)?)
            .bind(machine_key)
            .bind(&request.node_key)
            .bind(hostinfo.clone())
            .bind(key_expiry_unix_secs.map(|value| value as f64))
            .bind(i64::from(request.version))
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                r#"
                UPDATE oidc_auth_requests
                SET
                    node_id = $2,
                    updated_at = now()
                WHERE id = $1
                "#,
            )
            .bind(auth_id)
            .bind(u64_to_i64(node.id)?)
            .execute(&mut *tx)
            .await?;
            let route_principal = self.load_route_principal(node.principal_id).await?;
            self.sync_advertised_routes_tx(
                &mut tx,
                &node,
                route_principal.as_ref(),
                &hostinfo,
                &actor,
            )
            .await?;
            self.record_audit_event_tx(
                &mut tx,
                AuditEventKind::NodeRegistered,
                &actor,
                &format!("node/{}", node.id),
            )
            .await?;

            node.id
        };

        tx.commit().await?;
        self.notify_control_change().await;
        self.get_control_node(node_id).await
    }

    async fn upsert_principal_from_pending(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        pending: &sqlx::postgres::PgRow,
    ) -> AppResult<Principal> {
        let issuer = pending
            .get::<Option<String>, _>("principal_issuer")
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AppError::Unauthorized("OIDC authentication is missing an issuer".to_string())
            })?;
        let subject = pending
            .get::<Option<String>, _>("principal_sub")
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                AppError::Unauthorized("OIDC authentication is missing a subject".to_string())
            })?;
        let email = pending
            .get::<Option<String>, _>("principal_email")
            .filter(|value| !value.trim().is_empty());
        let login_name = email.clone().unwrap_or_else(|| subject.clone());
        let display_name = pending
            .get::<Option<String>, _>("principal_name")
            .filter(|value| !value.trim().is_empty())
            .or_else(|| email.clone())
            .unwrap_or_else(|| subject.clone());
        let groups = pending.get::<Value, _>("principal_groups");

        let row = sqlx::query(
            r#"
            INSERT INTO principals (
                provider,
                issuer,
                subject,
                login_name,
                display_name,
                email,
                groups
            )
            VALUES ('oidc', $1, $2, $3, $4, $5, $6)
            ON CONFLICT (provider, issuer, subject)
            DO UPDATE SET
                login_name = EXCLUDED.login_name,
                display_name = EXCLUDED.display_name,
                email = EXCLUDED.email,
                groups = EXCLUDED.groups,
                updated_at = now()
            RETURNING
                id,
                provider,
                issuer,
                subject,
                login_name,
                display_name,
                email,
                groups,
                EXTRACT(EPOCH FROM created_at)::bigint AS created_at_unix_secs
            "#,
        )
        .bind(&issuer)
        .bind(&subject)
        .bind(&login_name)
        .bind(&display_name)
        .bind(&email)
        .bind(groups)
        .fetch_one(&mut **tx)
        .await?;

        super::postgres::map_principal_row(row)
    }

    pub async fn touch_control_node(
        &self,
        machine_key: &str,
        request: &MapRequest,
    ) -> AppResult<ControlNodeRecord> {
        validate_control_machine_key(machine_key)?;
        validate_map_request(request)?;

        let key_expiry_unix_secs: Option<u64> = None;
        let actor = AuditActor {
            subject: format!("machine:{machine_key}"),
            mechanism: "ts2021".to_string(),
        };
        let mut tx = self.pool.begin().await?;
        let existing = sqlx::query(
            r#"
            SELECT
                c.node_id,
                c.disco_key,
                c.hostinfo,
                c.endpoints,
                n.status
            FROM node_control_state c
            INNER JOIN nodes n ON n.id = c.node_id
            WHERE c.machine_key = $1 AND c.node_key = $2
            FOR UPDATE OF c, n
            "#,
        )
        .bind(machine_key)
        .bind(&request.node_key)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            AppError::Unauthorized(
                "node key does not match the Noise session machine key".to_string(),
            )
        })?;
        let node_id = i64_to_u64(existing.get::<i64, _>("node_id"))?;
        let existing_disco_key = existing
            .get::<Option<String>, _>("disco_key")
            .unwrap_or_default();
        let existing_hostinfo = existing.get::<Option<Value>, _>("hostinfo");
        let existing_endpoints =
            serde_json::from_value::<Vec<String>>(existing.get::<Value, _>("endpoints"))?;
        let existing_status = existing.get::<String, _>("status");
        let requested_disco_key = request.disco_key.trim().to_string();
        let topology_changed = existing_disco_key != requested_disco_key
            || request
                .hostinfo
                .as_ref()
                .is_some_and(|hostinfo| existing_hostinfo.as_ref() != Some(hostinfo))
            || existing_endpoints != request.endpoints;
        let became_online = existing_status != NodeStatus::Online.as_str();

        sqlx::query(
            r#"
            UPDATE nodes
            SET
                status = $2,
                last_seen_unix_secs = $3,
                last_sync_at = now(),
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(u64_to_i64(node_id)?)
        .bind(NodeStatus::Online.as_str())
        .bind(u64_to_i64(now_unix_secs()?)?)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            UPDATE node_control_state
            SET
                disco_key = NULLIF($2, ''),
                hostinfo = COALESCE($3, hostinfo),
                endpoints = $4,
                key_expiry = COALESCE(to_timestamp($5), key_expiry),
                map_request_version = $6,
                last_control_seen_at = now(),
                last_map_poll_at = now(),
                updated_at = now()
            WHERE node_id = $1
            "#,
        )
        .bind(u64_to_i64(node_id)?)
        .bind(&request.disco_key)
        .bind(request.hostinfo.clone())
        .bind(serde_json::to_value(&request.endpoints)?)
        .bind(key_expiry_unix_secs.map(|value| value as f64))
        .bind(i64::from(request.version))
        .execute(&mut *tx)
        .await?;

        let node = load_node_tx(&mut tx, node_id).await?;
        let principal = self.load_route_principal(node.principal_id).await?;
        let routes_changed = if request.hostinfo.is_some() {
            self.sync_advertised_routes_tx(
                &mut tx,
                &node,
                principal.as_ref(),
                &coalesced_hostinfo(request.hostinfo.clone()),
                &actor,
            )
            .await?
        } else {
            false
        };

        tx.commit().await?;
        if topology_changed || became_online || routes_changed {
            self.notify_control_change().await;
        }

        self.get_control_node(node_id).await
    }

    async fn sync_advertised_routes_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        node: &Node,
        principal: Option<&Principal>,
        hostinfo: &Value,
        actor: &AuditActor,
    ) -> AppResult<bool> {
        let policy = load_policy_tx(tx).await?;
        let advertised_routes = parse_advertised_routes(hostinfo)?;
        let rows = sqlx::query(
            r#"
            SELECT id, node_id, prefix, advertised, approval, approved_by_policy, is_exit_node
            FROM routes
            WHERE node_id = $1
            ORDER BY id ASC
            FOR UPDATE
            "#,
        )
        .bind(u64_to_i64(node.id)?)
        .fetch_all(&mut **tx)
        .await?;
        let existing_routes = rows
            .into_iter()
            .map(super::postgres::map_route_row)
            .collect::<AppResult<Vec<_>>>()?;
        let planned_changes = plan_advertised_route_sync(
            &existing_routes,
            &advertised_routes,
            node,
            principal,
            &policy,
        )?;

        if planned_changes.is_empty() {
            return Ok(false);
        }

        for change in planned_changes {
            let route_id = if let Some(existing_id) = change.existing_id {
                sqlx::query(
                    r#"
                    UPDATE routes
                    SET
                        advertised = $2,
                        approval = $3,
                        approved_by_policy = $4,
                        is_exit_node = $5,
                        updated_at = now()
                    WHERE id = $1
                    "#,
                )
                .bind(u64_to_i64(existing_id)?)
                .bind(change.advertised)
                .bind(change.approval.as_str())
                .bind(change.approved_by_policy)
                .bind(change.is_exit_node)
                .execute(&mut **tx)
                .await?;
                existing_id
            } else {
                let row = sqlx::query(
                    r#"
                    INSERT INTO routes (
                        node_id,
                        prefix,
                        advertised,
                        approval,
                        approved_by_policy,
                        is_exit_node
                    )
                    VALUES ($1, $2, $3, $4, $5, $6)
                    RETURNING id
                    "#,
                )
                .bind(u64_to_i64(node.id)?)
                .bind(&change.prefix)
                .bind(change.advertised)
                .bind(change.approval.as_str())
                .bind(change.approved_by_policy)
                .bind(change.is_exit_node)
                .fetch_one(&mut **tx)
                .await?;
                let route_id = i64_to_u64(row.get::<i64, _>("id"))?;
                self.record_audit_event_tx(
                    tx,
                    AuditEventKind::RouteCreated,
                    actor,
                    &format!("route/{route_id}"),
                )
                .await?;
                route_id
            };

            if change.auto_approved {
                self.record_audit_event_tx(
                    tx,
                    AuditEventKind::RouteApproved,
                    actor,
                    &format!("route/{route_id}"),
                )
                .await?;
            }
        }

        Ok(true)
    }

    pub async fn list_control_nodes(&self) -> AppResult<Vec<ControlNodeRecord>> {
        let rows = sqlx::query(control_node_select_sql())
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(map_control_node_row).collect()
    }

    pub async fn get_control_node(&self, node_id: u64) -> AppResult<ControlNodeRecord> {
        let row = sqlx::query(control_node_select_sql_with_where("n.id = $1"))
            .bind(u64_to_i64(node_id)?)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => map_control_node_row(row),
            None => Err(AppError::NotFound(format!("control node {node_id}"))),
        }
    }

    pub async fn get_control_node_by_machine_key(
        &self,
        machine_key: &str,
    ) -> AppResult<Option<ControlNodeRecord>> {
        validate_control_machine_key(machine_key)?;

        let row = sqlx::query(control_node_select_sql_with_where("c.machine_key = $1"))
            .bind(machine_key)
            .fetch_optional(&self.pool)
            .await?;

        row.map(map_control_node_row).transpose()
    }

    pub async fn store_control_session(
        &self,
        node_id: u64,
        handle: &str,
        seq: i64,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            UPDATE node_control_state
            SET
                map_session_handle = $2,
                map_session_seq = $3,
                last_map_poll_at = now(),
                updated_at = now()
            WHERE node_id = $1
            "#,
        )
        .bind(u64_to_i64(node_id)?)
        .bind(handle)
        .bind(seq)
        .execute(&self.pool)
        .await?;

        self.notify_control_change().await;

        Ok(())
    }

    pub async fn has_control_node(&self, machine_key: &str) -> AppResult<bool> {
        validate_control_machine_key(machine_key)?;

        sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM node_control_state
                WHERE machine_key = $1
            )
            "#,
        )
        .bind(machine_key)
        .fetch_one(&self.pool)
        .await
        .map_err(AppError::from)
    }

    pub async fn allows_derp_client(&self, node_public: &str) -> AppResult<bool> {
        if node_public.trim().is_empty() {
            return Ok(false);
        }

        let exists = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM node_control_state c
                INNER JOIN nodes n ON n.id = c.node_id
                WHERE c.node_key = $1
                  AND n.status NOT IN ('disabled', 'expired')
            )
            "#,
        )
        .bind(node_public)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }
}

async fn apply_requested_tag_assignment_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    node_id: u64,
    assignment: &RequestedTagAssignment,
) -> AppResult<()> {
    sqlx::query(
        r#"
        UPDATE nodes
        SET
            principal_id = $2,
            tags = $3,
            tag_source = $4,
            updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(u64_to_i64(node_id)?)
    .bind(assignment.principal_id.map(u64_to_i64).transpose()?)
    .bind(serde_json::to_value(&assignment.tags)?)
    .bind(assignment.tag_source.as_str())
    .execute(&mut **tx)
    .await?;

    Ok(())
}

fn resolve_requested_tags_for_principal(
    policy: &AclPolicy,
    node: &Node,
    principal: &Principal,
    hostinfo: &Value,
) -> AppResult<RequestedTagAssignment> {
    let request_tags = parse_request_tags(hostinfo)?;
    if node.tag_source.is_server_forced() {
        if !hostinfo_has_explicit_request_tags(hostinfo) || request_tags == node.tags {
            return Ok(RequestedTagAssignment {
                tags: node.tags.clone(),
                principal_id: node.principal_id,
                tag_source: node.tag_source,
            });
        }

        return Err(server_tag_update_not_permitted_error());
    }

    if request_tags.is_empty() {
        return Ok(RequestedTagAssignment {
            tags: Vec::new(),
            principal_id: Some(principal.id),
            tag_source: NodeTagSource::None,
        });
    }

    let approved = policy.approved_request_tags(node, Some(principal), &request_tags)?;
    if approved.len() != request_tags.len() {
        let approved = approved.into_iter().collect::<BTreeSet<_>>();
        let rejected = request_tags
            .into_iter()
            .filter(|tag| !approved.contains(tag))
            .collect::<Vec<_>>();
        return Err(requested_tags_not_permitted_error(&rejected));
    }

    Ok(RequestedTagAssignment {
        tags: approved,
        principal_id: None,
        tag_source: NodeTagSource::Request,
    })
}

fn hostinfo_has_explicit_request_tags(hostinfo: &Value) -> bool {
    hostinfo
        .as_object()
        .is_some_and(|hostinfo| hostinfo.contains_key("RequestTags"))
}

fn server_tag_update_not_permitted_error() -> AppError {
    AppError::Unauthorized("requested tags cannot modify server-managed node tags".to_string())
}

fn validate_control_machine_key(machine_key: &str) -> AppResult<()> {
    if machine_key.trim().is_empty() {
        return Err(AppError::Unauthorized(
            "Noise session did not provide a machine public key".to_string(),
        ));
    }

    Ok(())
}

fn validate_register_request(request: &RegisterRequest) -> AppResult<()> {
    if request.version == 0 {
        return Err(AppError::InvalidRequest(
            "register request version must be greater than zero".to_string(),
        ));
    }

    if request.node_key.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "register request node key must not be empty".to_string(),
        ));
    }

    Ok(())
}

fn validate_map_request(request: &MapRequest) -> AppResult<()> {
    if request.version == 0 {
        return Err(AppError::InvalidRequest(
            "map request version must be greater than zero".to_string(),
        ));
    }

    if request.node_key.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "map request node key must not be empty".to_string(),
        ));
    }

    Ok(())
}

fn authenticate_protocol_auth_key(auth: Option<&RegisterResponseAuth>) -> AppResult<&str> {
    let Some(auth) = auth else {
        return Err(AppError::Unauthorized(
            "interactive registration is not supported; Auth.AuthKey is required".to_string(),
        ));
    };
    let auth_key = auth.auth_key.trim();
    if auth_key.is_empty() {
        return Err(AppError::Unauthorized(
            "interactive registration is not supported; Auth.AuthKey is required".to_string(),
        ));
    }

    Ok(auth_key)
}

fn control_node_select_sql() -> &'static str {
    control_node_select_sql_with_where("TRUE")
}

fn oidc_auth_request_select_sql_with_where(where_clause: &'static str) -> &'static str {
    match where_clause {
        "id = $1" => {
            r#"
            SELECT
                id,
                machine_key,
                node_key,
                oidc_state,
                oidc_nonce,
                pkce_verifier,
                principal_sub,
                principal_issuer,
                principal_email,
                principal_name,
                principal_groups,
                node_id,
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix_secs,
                EXTRACT(EPOCH FROM completed_at)::bigint AS completed_at_unix_secs
            FROM oidc_auth_requests
            WHERE id = $1
              AND expires_at > now()
            "#
        }
        _ => {
            r#"
            SELECT
                id,
                machine_key,
                node_key,
                oidc_state,
                oidc_nonce,
                pkce_verifier,
                principal_sub,
                principal_issuer,
                principal_email,
                principal_name,
                principal_groups,
                node_id,
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix_secs,
                EXTRACT(EPOCH FROM completed_at)::bigint AS completed_at_unix_secs
            FROM oidc_auth_requests
            WHERE oidc_state = $1
              AND expires_at > now()
            "#
        }
    }
}

fn ssh_auth_request_select_sql_with_where(where_clause: &'static str) -> &'static str {
    match where_clause {
        "id = $1" => {
            r#"
            SELECT
                id,
                src_node_id,
                dst_node_id,
                ssh_user,
                local_user,
                oidc_state,
                oidc_nonce,
                pkce_verifier,
                status,
                message,
                principal_issuer,
                principal_sub,
                principal_email,
                principal_name,
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix_secs,
                EXTRACT(EPOCH FROM resolved_at)::bigint AS resolved_at_unix_secs
            FROM ssh_auth_requests
            WHERE id = $1
            "#
        }
        _ => {
            r#"
            SELECT
                id,
                src_node_id,
                dst_node_id,
                ssh_user,
                local_user,
                oidc_state,
                oidc_nonce,
                pkce_verifier,
                status,
                message,
                principal_issuer,
                principal_sub,
                principal_email,
                principal_name,
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix_secs,
                EXTRACT(EPOCH FROM resolved_at)::bigint AS resolved_at_unix_secs
            FROM ssh_auth_requests
            WHERE oidc_state = $1
              AND expires_at > now()
            "#
        }
    }
}

fn control_node_select_sql_with_where(where_clause: &'static str) -> &'static str {
    match where_clause {
        "TRUE" => {
            r#"
            SELECT
                n.id,
                n.stable_id,
                n.name,
                n.hostname,
                n.auth_key_id,
                n.principal_id,
                n.ipv4,
                n.ipv6,
                n.status,
                n.tags,
                n.tag_source,
                n.last_seen_unix_secs,
                EXTRACT(EPOCH FROM n.session_expires_at)::bigint AS session_expires_at_unix_secs,
                EXTRACT(EPOCH FROM n.created_at)::bigint AS created_at_unix_secs,
                c.machine_key,
                c.node_key,
                COALESCE(c.disco_key, '') AS disco_key,
                c.hostinfo,
                c.endpoints,
                EXTRACT(EPOCH FROM c.key_expiry)::bigint AS key_expiry_unix_secs,
                c.map_request_version,
                p.id AS principal_row_id,
                p.provider AS principal_provider,
                p.issuer AS principal_db_issuer,
                p.subject AS principal_subject,
                p.login_name AS principal_login_name,
                p.display_name AS principal_display_name,
                p.email AS principal_db_email,
                p.groups AS principal_db_groups,
                EXTRACT(EPOCH FROM p.created_at)::bigint AS principal_created_at_unix_secs
            FROM nodes n
            INNER JOIN node_control_state c ON c.node_id = n.id
            LEFT JOIN principals p ON p.id = n.principal_id
            ORDER BY n.id ASC
            "#
        }
        "n.id = $1" => {
            r#"
            SELECT
                n.id,
                n.stable_id,
                n.name,
                n.hostname,
                n.auth_key_id,
                n.principal_id,
                n.ipv4,
                n.ipv6,
                n.status,
                n.tags,
                n.tag_source,
                n.last_seen_unix_secs,
                EXTRACT(EPOCH FROM n.session_expires_at)::bigint AS session_expires_at_unix_secs,
                EXTRACT(EPOCH FROM n.created_at)::bigint AS created_at_unix_secs,
                c.machine_key,
                c.node_key,
                COALESCE(c.disco_key, '') AS disco_key,
                c.hostinfo,
                c.endpoints,
                EXTRACT(EPOCH FROM c.key_expiry)::bigint AS key_expiry_unix_secs,
                c.map_request_version,
                p.id AS principal_row_id,
                p.provider AS principal_provider,
                p.issuer AS principal_db_issuer,
                p.subject AS principal_subject,
                p.login_name AS principal_login_name,
                p.display_name AS principal_display_name,
                p.email AS principal_db_email,
                p.groups AS principal_db_groups,
                EXTRACT(EPOCH FROM p.created_at)::bigint AS principal_created_at_unix_secs
            FROM nodes n
            INNER JOIN node_control_state c ON c.node_id = n.id
            LEFT JOIN principals p ON p.id = n.principal_id
            WHERE n.id = $1
            "#
        }
        _ => {
            r#"
            SELECT
                n.id,
                n.stable_id,
                n.name,
                n.hostname,
                n.auth_key_id,
                n.principal_id,
                n.ipv4,
                n.ipv6,
                n.status,
                n.tags,
                n.tag_source,
                n.last_seen_unix_secs,
                EXTRACT(EPOCH FROM n.session_expires_at)::bigint AS session_expires_at_unix_secs,
                EXTRACT(EPOCH FROM n.created_at)::bigint AS created_at_unix_secs,
                c.machine_key,
                c.node_key,
                COALESCE(c.disco_key, '') AS disco_key,
                c.hostinfo,
                c.endpoints,
                EXTRACT(EPOCH FROM c.key_expiry)::bigint AS key_expiry_unix_secs,
                c.map_request_version,
                p.id AS principal_row_id,
                p.provider AS principal_provider,
                p.issuer AS principal_db_issuer,
                p.subject AS principal_subject,
                p.login_name AS principal_login_name,
                p.display_name AS principal_display_name,
                p.email AS principal_db_email,
                p.groups AS principal_db_groups,
                EXTRACT(EPOCH FROM p.created_at)::bigint AS principal_created_at_unix_secs
            FROM nodes n
            INNER JOIN node_control_state c ON c.node_id = n.id
            LEFT JOIN principals p ON p.id = n.principal_id
            WHERE c.machine_key = $1
            "#
        }
    }
}

fn map_control_node_row(row: sqlx::postgres::PgRow) -> AppResult<ControlNodeRecord> {
    let status = row.get::<String, _>("status");
    let tags = serde_json::from_value::<Vec<String>>(row.get::<Value, _>("tags"))?;
    let tag_source = row.get::<String, _>("tag_source");
    let endpoints = serde_json::from_value::<Vec<String>>(row.get::<Value, _>("endpoints"))?;
    let hostinfo = row.get::<Value, _>("hostinfo");

    Ok(ControlNodeRecord {
        node: Node {
            id: i64_to_u64(row.get::<i64, _>("id"))?,
            stable_id: row.get("stable_id"),
            name: row.get("name"),
            hostname: row.get("hostname"),
            auth_key_id: row.get("auth_key_id"),
            principal_id: row
                .get::<Option<i64>, _>("principal_id")
                .map(i64_to_u64)
                .transpose()?,
            ipv4: row.get("ipv4"),
            ipv6: row.get("ipv6"),
            status: NodeStatus::parse(&status).ok_or_else(|| {
                AppError::Bootstrap(format!("unsupported node status in database: {status}"))
            })?,
            tags,
            tag_source: NodeTagSource::parse(&tag_source).ok_or_else(|| {
                AppError::Bootstrap(format!(
                    "unsupported node tag source in database: {tag_source}"
                ))
            })?,
            last_seen_unix_secs: row
                .get::<Option<i64>, _>("last_seen_unix_secs")
                .map(i64_to_u64)
                .transpose()?,
        },
        principal: map_optional_principal_row(&row)?,
        machine_key: row.get("machine_key"),
        node_key: row.get("node_key"),
        disco_key: row.get("disco_key"),
        hostinfo: if hostinfo.is_null() {
            None
        } else {
            Some(hostinfo)
        },
        endpoints,
        key_expiry_unix_secs: row
            .get::<Option<i64>, _>("key_expiry_unix_secs")
            .map(i64_to_u64)
            .transpose()?,
        map_request_version: i64_to_u32(row.get::<i64, _>("map_request_version"))?,
        session_expires_at_unix_secs: row
            .get::<Option<i64>, _>("session_expires_at_unix_secs")
            .map(i64_to_u64)
            .transpose()?,
        created_at_unix_secs: i64_to_u64(row.get::<i64, _>("created_at_unix_secs"))?,
    })
}

fn map_oidc_auth_request_row(row: sqlx::postgres::PgRow) -> AppResult<PendingOidcAuthRequest> {
    Ok(PendingOidcAuthRequest {
        auth_id: row.get("id"),
        machine_key: row.get("machine_key"),
        node_key: row.get("node_key"),
        oidc_state: row.get("oidc_state"),
        oidc_nonce: row.get("oidc_nonce"),
        pkce_verifier: row.get("pkce_verifier"),
        principal_issuer: row.get("principal_issuer"),
        principal_sub: row.get("principal_sub"),
        principal_email: row.get("principal_email"),
        principal_name: row.get("principal_name"),
        principal_groups: serde_json::from_value(row.get::<Value, _>("principal_groups"))?,
        node_id: row
            .get::<Option<i64>, _>("node_id")
            .map(i64_to_u64)
            .transpose()?,
        expires_at_unix_secs: i64_to_u64(row.get::<i64, _>("expires_at_unix_secs"))?,
        completed_at_unix_secs: row
            .get::<Option<i64>, _>("completed_at_unix_secs")
            .map(i64_to_u64)
            .transpose()?,
    })
}

fn map_ssh_auth_request_row(row: sqlx::postgres::PgRow) -> AppResult<PendingSshAuthRequest> {
    Ok(PendingSshAuthRequest {
        auth_id: row.get("id"),
        src_node_id: i64_to_u64(row.get::<i64, _>("src_node_id"))?,
        dst_node_id: i64_to_u64(row.get::<i64, _>("dst_node_id"))?,
        ssh_user: row.get("ssh_user"),
        local_user: row.get("local_user"),
        oidc_state: row.get("oidc_state"),
        oidc_nonce: row.get("oidc_nonce"),
        pkce_verifier: row.get("pkce_verifier"),
        status: SshAuthRequestStatus::parse(&row.get::<String, _>("status"))?,
        message: row.get("message"),
        principal_issuer: row.get("principal_issuer"),
        principal_sub: row.get("principal_sub"),
        principal_email: row.get("principal_email"),
        principal_name: row.get("principal_name"),
        expires_at_unix_secs: i64_to_u64(row.get::<i64, _>("expires_at_unix_secs"))?,
        resolved_at_unix_secs: row
            .get::<Option<i64>, _>("resolved_at_unix_secs")
            .map(i64_to_u64)
            .transpose()?,
    })
}

fn ssh_check_audit_target(
    src_node_id: u64,
    dst_node_id: u64,
    ssh_user: &str,
    local_user: &str,
) -> String {
    if ssh_user.is_empty() && local_user.is_empty() {
        return format!("ssh-check/{src_node_id}->{dst_node_id}");
    }

    format!("ssh-check/{src_node_id}->{dst_node_id}:{ssh_user}->{local_user}")
}

fn map_optional_principal_row(row: &sqlx::postgres::PgRow) -> AppResult<Option<Principal>> {
    let Some(id) = row.get::<Option<i64>, _>("principal_row_id") else {
        return Ok(None);
    };

    Ok(Some(Principal {
        id: i64_to_u64(id)?,
        provider: row.get("principal_provider"),
        issuer: row.get("principal_db_issuer"),
        subject: row.get("principal_subject"),
        login_name: row.get("principal_login_name"),
        display_name: row.get("principal_display_name"),
        email: row.get("principal_db_email"),
        groups: serde_json::from_value(row.get::<Value, _>("principal_db_groups"))?,
        created_at_unix_secs: row
            .get::<Option<i64>, _>("principal_created_at_unix_secs")
            .map(i64_to_u64)
            .transpose()?
            .ok_or_else(|| {
                AppError::Bootstrap(
                    "control node query returned an incomplete principal row".to_string(),
                )
            })?,
    }))
}

async fn load_policy_tx(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> AppResult<AclPolicy> {
    let row = sqlx::query("SELECT policy FROM control_plane_state WHERE id = $1")
        .bind("global")
        .fetch_one(&mut **tx)
        .await?;

    let value = row.get::<Value, _>("policy");
    let policy = serde_json::from_value::<AclPolicy>(value)?;
    policy.validate()?;
    Ok(policy)
}

async fn load_node_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    node_id: u64,
) -> AppResult<Node> {
    let row = sqlx::query(
        r#"
        SELECT
            id,
            stable_id,
            name,
            hostname,
            auth_key_id,
            principal_id,
            ipv4,
            ipv6,
            status,
            tags,
            tag_source,
            last_seen_unix_secs
        FROM nodes
        WHERE id = $1
        "#,
    )
    .bind(u64_to_i64(node_id)?)
    .fetch_one(&mut **tx)
    .await?;

    super::postgres::map_node_row(row)
}

fn coalesced_hostinfo(hostinfo: Option<Value>) -> Value {
    hostinfo.unwrap_or(Value::Object(Default::default()))
}

fn parse_request_tags(hostinfo: &Value) -> AppResult<Vec<String>> {
    match hostinfo.get("RequestTags") {
        Some(Value::Null) | None => Ok(Vec::new()),
        Some(tags) => normalize_acl_tags(&serde_json::from_value::<Vec<String>>(tags.clone())?),
    }
}

fn parse_advertised_routes(hostinfo: &Value) -> AppResult<Vec<AdvertisedRoute>> {
    let advertised = hostinfo
        .get("RoutableIPs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut routes = BTreeSet::new();

    for value in advertised {
        let prefix = value.as_str().ok_or_else(|| {
            AppError::InvalidRequest(
                "hostinfo RoutableIPs entries must be CIDR strings".to_string(),
            )
        })?;
        validate_route_prefix(prefix)?;
        routes.insert(AdvertisedRoute {
            prefix: prefix.to_string(),
            is_exit_node: matches!(prefix, "0.0.0.0/0" | "::/0"),
        });
    }

    Ok(routes.into_iter().collect())
}

fn requested_tags_not_permitted_error(tags: &[String]) -> AppError {
    AppError::Unauthorized(format!(
        "requested tags [{}] are invalid or not permitted",
        tags.join(", ")
    ))
}

fn plan_advertised_route_sync(
    existing_routes: &[Route],
    advertised_routes: &[AdvertisedRoute],
    node: &Node,
    principal: Option<&Principal>,
    policy: &AclPolicy,
) -> AppResult<Vec<PlannedAdvertisedRouteChange>> {
    let mut existing_by_prefix = BTreeMap::<String, &Route>::new();
    for route in existing_routes {
        existing_by_prefix
            .entry(route.prefix.clone())
            .or_insert(route);
    }

    let mut changes = Vec::new();

    for advertised in advertised_routes {
        let current = existing_by_prefix.remove(&advertised.prefix);
        let (approval, approved_by_policy, auto_approved) =
            desired_advertised_route_state(current, advertised, node, principal, policy)?;
        let should_write = match current {
            Some(route) => {
                !route.advertised
                    || route.approval != approval
                    || route.approved_by_policy != approved_by_policy
                    || route.is_exit_node != advertised.is_exit_node
            }
            None => true,
        };

        if should_write {
            changes.push(PlannedAdvertisedRouteChange {
                existing_id: current.map(|route| route.id),
                prefix: advertised.prefix.clone(),
                advertised: true,
                approval,
                approved_by_policy,
                is_exit_node: advertised.is_exit_node,
                auto_approved,
            });
        }
    }

    for route in existing_by_prefix.into_values() {
        if !route.advertised {
            continue;
        }

        changes.push(PlannedAdvertisedRouteChange {
            existing_id: Some(route.id),
            prefix: route.prefix.clone(),
            advertised: false,
            approval: route.approval.clone(),
            approved_by_policy: route.approved_by_policy,
            is_exit_node: route.is_exit_node,
            auto_approved: false,
        });
    }

    changes.sort_by(|left, right| left.prefix.cmp(&right.prefix));
    Ok(changes)
}

fn desired_advertised_route_state(
    current: Option<&Route>,
    advertised: &AdvertisedRoute,
    node: &Node,
    principal: Option<&Principal>,
    policy: &AclPolicy,
) -> AppResult<(RouteApproval, bool, bool)> {
    let candidate = Route {
        id: current.map(|route| route.id).unwrap_or(0),
        node_id: node.id,
        prefix: advertised.prefix.clone(),
        advertised: true,
        approval: current
            .map(|route| route.approval.clone())
            .unwrap_or(RouteApproval::Pending),
        approved_by_policy: current.is_some_and(|route| route.approved_by_policy),
        is_exit_node: advertised.is_exit_node,
    };
    let should_auto_approve = policy.auto_approves_route(node, principal, &candidate)?;

    let desired = match current {
        Some(route) if should_auto_approve => match (&route.approval, route.approved_by_policy) {
            (RouteApproval::Pending, _) => (RouteApproval::Approved, true, true),
            (RouteApproval::Rejected, true) => (RouteApproval::Approved, true, true),
            (RouteApproval::Approved, true) => (RouteApproval::Approved, true, false),
            (_, false) => (route.approval.clone(), false, false),
        },
        Some(route) if route.approved_by_policy => (RouteApproval::Pending, false, false),
        Some(route) => (route.approval.clone(), route.approved_by_policy, false),
        None if should_auto_approve => (RouteApproval::Approved, true, true),
        None => (RouteApproval::Pending, false, false),
    };

    Ok(desired)
}

fn protocol_hostname(hostinfo: &Value) -> Option<String> {
    let hostname = hostinfo
        .get("Hostname")
        .and_then(Value::as_str)
        .map(sanitize_hostname)?;

    if hostname.is_empty() {
        None
    } else {
        Some(hostname)
    }
}

fn sanitize_hostname(value: &str) -> String {
    let mut hostname = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            hostname.push(character.to_ascii_lowercase());
        } else if character == '-' || character == '_' || character == '.' {
            hostname.push('-');
        }
    }

    hostname.trim_matches('-').to_string()
}

fn fallback_protocol_hostname(machine_key: &str) -> String {
    format!("node-{}", short_machine_key(machine_key))
}

fn short_machine_key(machine_key: &str) -> &str {
    machine_key
        .strip_prefix("mkey:")
        .unwrap_or(machine_key)
        .get(..8)
        .unwrap_or("node")
}

fn parse_rfc3339_unix_secs(value: &str) -> AppResult<Option<u64>> {
    if value.trim().is_empty() {
        return Ok(None);
    }

    let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|err| {
        AppError::InvalidRequest(format!("invalid RFC3339 timestamp {value}: {err}"))
    })?;
    match u64::try_from(parsed.unix_timestamp()) {
        Ok(timestamp) => Ok(Some(timestamp)),
        Err(_) => Ok(None),
    }
}

fn now_unix_secs() -> AppResult<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| AppError::Bootstrap(format!("system clock error: {err}")))?;
    Ok(duration.as_secs())
}

fn i64_to_u64(value: i64) -> AppResult<u64> {
    u64::try_from(value)
        .map_err(|_| AppError::Bootstrap(format!("value {value} cannot be represented as u64")))
}

fn i64_to_u32(value: i64) -> AppResult<u32> {
    u32::try_from(value)
        .map_err(|_| AppError::Bootstrap(format!("value {value} cannot be represented as u32")))
}

fn u64_to_i64(value: u64) -> AppResult<i64> {
    i64::try_from(value)
        .map_err(|_| AppError::Bootstrap(format!("value {value} cannot be represented as i64")))
}

fn random_token(byte_len: usize) -> AppResult<String> {
    let mut bytes = vec![0_u8; byte_len];
    random::fill(&mut bytes)
        .map_err(|err| AppError::Bootstrap(format!("failed to generate random token: {err}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

async fn ensure_node_exists(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    node_id: u64,
    resource_name: &str,
) -> AppResult<()> {
    let exists = sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM nodes WHERE id = $1)")
        .bind(u64_to_i64(node_id)?)
        .fetch_one(&mut **tx)
        .await?;

    if exists {
        Ok(())
    } else {
        Err(AppError::NotFound(format!("{resource_name} {node_id}")))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;
    use serde_json::json;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn node(id: u64, principal_id: Option<u64>) -> Node {
        Node {
            id,
            stable_id: format!("stable-{id}"),
            name: format!("node-{id}"),
            hostname: format!("node-{id}"),
            auth_key_id: None,
            principal_id,
            ipv4: Some(format!("100.64.0.{id}")),
            ipv6: None,
            status: NodeStatus::Online,
            tags: Vec::new(),
            tag_source: NodeTagSource::None,
            last_seen_unix_secs: None,
        }
    }

    fn tagged_node(id: u64, principal_id: Option<u64>, tags: &[&str]) -> Node {
        Node {
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            ..node(id, principal_id)
        }
    }

    fn principal(id: u64, login_name: &str) -> Principal {
        Principal {
            id,
            provider: "oidc".to_string(),
            issuer: Some("https://issuer.example.com".to_string()),
            subject: Some(format!("subject-{id}")),
            login_name: login_name.to_string(),
            display_name: login_name.to_string(),
            email: Some(login_name.to_string()),
            groups: Vec::new(),
            created_at_unix_secs: 1,
        }
    }

    fn route(
        id: u64,
        node_id: u64,
        prefix: &str,
        advertised: bool,
        approval: RouteApproval,
        approved_by_policy: bool,
        is_exit_node: bool,
    ) -> Route {
        Route {
            id,
            node_id,
            prefix: prefix.to_string(),
            advertised,
            approval,
            approved_by_policy,
            is_exit_node,
        }
    }

    #[test]
    fn parse_advertised_routes_deduplicates_and_marks_exit_routes() -> TestResult {
        let hostinfo = json!({
            "RoutableIPs": ["10.0.0.0/24", "10.0.0.0/24", "0.0.0.0/0", "::/0"]
        });

        let routes = parse_advertised_routes(&hostinfo)?;

        assert_eq!(
            routes,
            vec![
                AdvertisedRoute {
                    prefix: "0.0.0.0/0".to_string(),
                    is_exit_node: true,
                },
                AdvertisedRoute {
                    prefix: "10.0.0.0/24".to_string(),
                    is_exit_node: false,
                },
                AdvertisedRoute {
                    prefix: "::/0".to_string(),
                    is_exit_node: true,
                },
            ]
        );

        Ok(())
    }

    #[test]
    fn advertised_route_sync_auto_approves_pending_routes_for_matching_principal() -> TestResult {
        let node = node(1, Some(10));
        let principal = principal(10, "alice@example.com");
        let existing = vec![route(
            50,
            node.id,
            "10.1.0.0/24",
            true,
            RouteApproval::Pending,
            false,
            false,
        )];
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: crate::domain::AutoApproverPolicy {
                routes: BTreeMap::from([("10.0.0.0/8".to_string(), vec!["alice@".to_string()])]),
                exit_node: Vec::new(),
            },
            ssh_rules: Vec::new(),
        };

        let plan = plan_advertised_route_sync(
            &existing,
            &[AdvertisedRoute {
                prefix: "10.1.0.0/24".to_string(),
                is_exit_node: false,
            }],
            &node,
            Some(&principal),
            &policy,
        )?;

        assert_eq!(
            plan,
            vec![PlannedAdvertisedRouteChange {
                existing_id: Some(50),
                prefix: "10.1.0.0/24".to_string(),
                advertised: true,
                approval: RouteApproval::Approved,
                approved_by_policy: true,
                is_exit_node: false,
                auto_approved: true,
            }]
        );

        Ok(())
    }

    #[test]
    fn advertised_route_sync_deactivates_withdrawn_routes_without_clearing_manual_approval()
    -> TestResult {
        let node = node(1, Some(10));
        let principal = principal(10, "alice@example.com");
        let existing = vec![route(
            60,
            node.id,
            "10.2.0.0/24",
            true,
            RouteApproval::Approved,
            false,
            false,
        )];
        let policy = AclPolicy::default();

        let plan = plan_advertised_route_sync(&existing, &[], &node, Some(&principal), &policy)?;

        assert_eq!(
            plan,
            vec![PlannedAdvertisedRouteChange {
                existing_id: Some(60),
                prefix: "10.2.0.0/24".to_string(),
                advertised: false,
                approval: RouteApproval::Approved,
                approved_by_policy: false,
                is_exit_node: false,
                auto_approved: false,
            }]
        );

        Ok(())
    }

    #[test]
    fn advertised_route_sync_does_not_promote_tagged_nodes_via_group_principals() -> TestResult {
        let node = tagged_node(1, Some(10), &["tag:router"]);
        let principal = principal(10, "alice@example.com");
        let policy = AclPolicy {
            groups: vec![crate::domain::PolicySubject {
                name: "ops".to_string(),
                members: vec!["alice@".to_string()],
            }],
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: crate::domain::AutoApproverPolicy {
                routes: BTreeMap::from([("10.0.0.0/8".to_string(), vec!["group:ops".to_string()])]),
                exit_node: Vec::new(),
            },
            ssh_rules: Vec::new(),
        };

        let plan = plan_advertised_route_sync(
            &[],
            &[AdvertisedRoute {
                prefix: "10.3.0.0/24".to_string(),
                is_exit_node: false,
            }],
            &node,
            Some(&principal),
            &policy,
        )?;

        assert_eq!(
            plan,
            vec![PlannedAdvertisedRouteChange {
                existing_id: None,
                prefix: "10.3.0.0/24".to_string(),
                advertised: true,
                approval: RouteApproval::Pending,
                approved_by_policy: false,
                is_exit_node: false,
                auto_approved: false,
            }]
        );

        Ok(())
    }

    #[test]
    fn parse_request_tags_normalizes_and_deduplicates() -> TestResult {
        let hostinfo = json!({
            "RequestTags": ["tag:prod", " tag:prod ", "tag:relay"]
        });

        let tags = parse_request_tags(&hostinfo)?;

        assert_eq!(tags, vec!["tag:prod".to_string(), "tag:relay".to_string()]);

        Ok(())
    }

    #[test]
    fn resolve_requested_tags_for_principal_rejects_unowned_tags() -> TestResult {
        let node = node(1, Some(10));
        let principal = principal(10, "alice@example.com");
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::from([("tag:prod".to_string(), vec!["bob@".to_string()])]),
            auto_approvers: crate::domain::AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };
        let hostinfo = json!({
            "RequestTags": ["tag:prod"]
        });

        let error =
            match resolve_requested_tags_for_principal(&policy, &node, &principal, &hostinfo) {
                Ok(_) => {
                    return Err(
                        std::io::Error::other("unowned request tags should be rejected").into(),
                    );
                }
                Err(error) => error,
            };

        assert_eq!(
            error.to_string(),
            "unauthorized: requested tags [tag:prod] are invalid or not permitted"
        );

        Ok(())
    }

    #[test]
    fn resolve_requested_tags_for_principal_clears_tags_when_request_is_empty() -> TestResult {
        let node = tagged_node(1, None, &["tag:relay"]);
        let principal = principal(10, "alice@example.com");
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::from([("tag:relay".to_string(), vec!["alice@".to_string()])]),
            auto_approvers: crate::domain::AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };
        let hostinfo = json!({
            "RequestTags": []
        });

        let assignment =
            resolve_requested_tags_for_principal(&policy, &node, &principal, &hostinfo)?;

        assert_eq!(
            assignment,
            RequestedTagAssignment {
                tags: Vec::new(),
                principal_id: Some(principal.id),
                tag_source: NodeTagSource::None,
            }
        );

        Ok(())
    }

    #[test]
    fn resolve_requested_tags_for_principal_preserves_server_managed_tags_without_explicit_field()
    -> TestResult {
        let mut node = tagged_node(1, None, &["tag:relay"]);
        node.tag_source = NodeTagSource::AuthKey;
        let principal = principal(10, "alice@example.com");

        let assignment = resolve_requested_tags_for_principal(
            &AclPolicy::default(),
            &node,
            &principal,
            &json!({ "Hostname": "relay-1" }),
        )?;

        assert_eq!(
            assignment,
            RequestedTagAssignment {
                tags: vec!["tag:relay".to_string()],
                principal_id: None,
                tag_source: NodeTagSource::AuthKey,
            }
        );

        Ok(())
    }

    #[test]
    fn resolve_requested_tags_for_principal_rejects_server_managed_tag_changes() -> TestResult {
        let mut node = tagged_node(1, None, &["tag:relay"]);
        node.tag_source = NodeTagSource::Admin;
        let principal = principal(10, "alice@example.com");

        let error = match resolve_requested_tags_for_principal(
            &AclPolicy::default(),
            &node,
            &principal,
            &json!({ "RequestTags": [] }),
        ) {
            Ok(_) => {
                return Err(std::io::Error::other(
                    "server-managed tags must not be cleared by request tags",
                )
                .into());
            }
            Err(error) => error,
        };

        assert_eq!(
            error.to_string(),
            "unauthorized: requested tags cannot modify server-managed node tags"
        );

        Ok(())
    }
}
