use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use graviola::hashing::{Hash, Sha256};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::{PgPool, Row};
use tokio::sync::watch;
use tokio::time;
use tracing::warn;
use uuid::Uuid;

use crate::config::{DatabaseConfig, NetworkConfig};
use crate::domain::{
    AclPolicy, AuditActor, AuditEvent, AuditEventKind, AuthKey, AuthKeyState, BackupAuthKey,
    BackupRestoreResult, BackupSnapshot, DnsConfig, IssuedAuthKey, Node, NodeHeartbeat, NodeMap,
    NodeRegistration, NodeStatus, NodeTagSource, Principal, Route, RouteApproval,
    normalize_acl_tags, validate_route_prefix,
};
use crate::error::{AppError, AppResult};

const BACKUP_FORMAT_VERSION: u32 = 3;
const CONTROL_PLANE_STATE_ID: &str = "global";
const CONTROL_UPDATE_CHANNEL: &str = "rscale_control_updates";
const CONTROL_LISTENER_RETRY_INTERVAL_SECS: u64 = 1;
const CONTROL_NOTIFY_TIMEOUT_SECS: u64 = 1;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct PostgresStore {
    pub(super) pool: PgPool,
    pub(super) network: NetworkConfig,
    pub(super) control_updates: watch::Sender<u64>,
    pub(super) control_instance_id: String,
}

impl PostgresStore {
    pub async fn connect(config: &DatabaseConfig, network: &NetworkConfig) -> AppResult<Self> {
        let url = config.url.clone().ok_or_else(|| {
            AppError::InvalidConfig("database.url is required for PostgreSQL".to_string())
        })?;

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect(&url)
            .await?;

        MIGRATOR.run(&pool).await?;
        let (control_updates, _) = watch::channel(0_u64);
        let store = Self {
            pool,
            network: network.clone(),
            control_updates,
            control_instance_id: Uuid::new_v4().to_string(),
        };
        store.spawn_control_listener();

        Ok(store)
    }

    pub async fn ping(&self) -> AppResult<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn subscribe_control_events(&self) -> watch::Receiver<u64> {
        self.control_updates.subscribe()
    }

    pub(super) async fn notify_control_change(&self) {
        emit_local_control_change(&self.control_updates);

        match time::timeout(
            time::Duration::from_secs(CONTROL_NOTIFY_TIMEOUT_SECS),
            sqlx::query("SELECT pg_notify($1, $2)")
                .bind(CONTROL_UPDATE_CHANNEL)
                .bind(&self.control_instance_id)
                .execute(&self.pool),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                warn!(
                    channel = CONTROL_UPDATE_CHANNEL,
                    instance_id = %self.control_instance_id,
                    error = %err,
                    "failed to publish PostgreSQL control-plane notification"
                );
            }
            Err(_) => {
                warn!(
                    channel = CONTROL_UPDATE_CHANNEL,
                    instance_id = %self.control_instance_id,
                    timeout_secs = CONTROL_NOTIFY_TIMEOUT_SECS,
                    "timed out publishing PostgreSQL control-plane notification"
                );
            }
        }
    }

    fn spawn_control_listener(&self) {
        let pool = self.pool.clone();
        let control_updates = self.control_updates.clone();
        let control_instance_id = self.control_instance_id.clone();

        tokio::spawn(async move {
            loop {
                let mut listener = match PgListener::connect_with(&pool).await {
                    Ok(listener) => listener,
                    Err(err) => {
                        if pool.is_closed() {
                            break;
                        }
                        warn!(
                            channel = CONTROL_UPDATE_CHANNEL,
                            instance_id = %control_instance_id,
                            error = %err,
                            "failed to connect PostgreSQL control-plane listener"
                        );
                        time::sleep(time::Duration::from_secs(
                            CONTROL_LISTENER_RETRY_INTERVAL_SECS,
                        ))
                        .await;
                        continue;
                    }
                };

                if let Err(err) = listener.listen(CONTROL_UPDATE_CHANNEL).await {
                    if pool.is_closed() {
                        break;
                    }
                    warn!(
                        channel = CONTROL_UPDATE_CHANNEL,
                        instance_id = %control_instance_id,
                        error = %err,
                        "failed to subscribe PostgreSQL control-plane listener"
                    );
                    time::sleep(time::Duration::from_secs(
                        CONTROL_LISTENER_RETRY_INTERVAL_SECS,
                    ))
                    .await;
                    continue;
                }

                loop {
                    match listener.recv().await {
                        Ok(notification) => {
                            apply_remote_control_notification(
                                &control_updates,
                                &control_instance_id,
                                notification.payload(),
                            );
                        }
                        Err(err) => {
                            if pool.is_closed() {
                                return;
                            }
                            warn!(
                                channel = CONTROL_UPDATE_CHANNEL,
                                instance_id = %control_instance_id,
                                error = %err,
                                "PostgreSQL control-plane listener stopped; reconnecting"
                            );
                            time::sleep(time::Duration::from_secs(
                                CONTROL_LISTENER_RETRY_INTERVAL_SECS,
                            ))
                            .await;
                            break;
                        }
                    }
                }
            }
        });
    }

    pub async fn list_nodes(&self) -> AppResult<Vec<Node>> {
        let rows = sqlx::query(
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
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(map_node_row).collect()
    }

    pub async fn list_admin_nodes(&self) -> AppResult<Vec<Node>> {
        let now_unix_secs = now_unix_secs()?;
        let rows = sqlx::query(
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
                EXTRACT(EPOCH FROM session_expires_at)::bigint AS session_expires_at_unix_secs,
                last_seen_unix_secs
            FROM nodes
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                map_admin_node_row(
                    row,
                    now_unix_secs,
                    self.network.node_online_window_secs,
                )
            })
            .collect()
    }

    pub async fn count_nodes(&self) -> AppResult<u64> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nodes")
            .fetch_one(&self.pool)
            .await?;
        i64_to_u64(count)
    }

    pub async fn get_node(&self, node_id: u64) -> AppResult<Node> {
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
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => map_node_row(row),
            None => Err(AppError::NotFound(format!("node {node_id}"))),
        }
    }

    pub async fn get_admin_node(&self, node_id: u64) -> AppResult<Node> {
        let now_unix_secs = now_unix_secs()?;
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
                EXTRACT(EPOCH FROM session_expires_at)::bigint AS session_expires_at_unix_secs,
                last_seen_unix_secs
            FROM nodes
            WHERE id = $1
            "#,
        )
        .bind(u64_to_i64(node_id)?)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => map_admin_node_row(
                row,
                now_unix_secs,
                self.network.node_online_window_secs,
            ),
            None => Err(AppError::NotFound(format!("node {node_id}"))),
        }
    }

    pub async fn create_node(
        &self,
        input: &CreateNodeInput,
        actor: &AuditActor,
    ) -> AppResult<Node> {
        validate_create_node_input(input)?;
        let tags = normalize_acl_tags(&input.tags)?;
        let mut tx = self.pool.begin().await?;
        let (ipv4, ipv6) = self
            .allocate_node_addresses(&mut tx, input.ipv4.as_deref(), input.ipv6.as_deref())
            .await?;
        let node = self
            .insert_node(
                &mut tx,
                InsertNode {
                    stable_id: Uuid::new_v4().to_string(),
                    name: input.name.clone(),
                    hostname: input.hostname.clone(),
                    auth_key_id: None,
                    principal_id: None,
                    session_secret_hash: None,
                    session_expires_at_unix_secs: None,
                    ipv4,
                    ipv6,
                    status: NodeStatus::Pending,
                    tags: tags.clone(),
                    tag_source: node_tag_source_for_tags(tags.as_slice(), NodeTagSource::Admin),
                    last_seen_unix_secs: None,
                },
            )
            .await?;
        tx.commit().await?;
        self.record_audit_event(
            AuditEventKind::NodeRegistered,
            actor,
            &format!("node/{}", node.id),
        )
        .await?;
        self.notify_control_change().await;

        Ok(node)
    }

    pub async fn update_node(
        &self,
        node_id: u64,
        input: &UpdateNodeInput,
        actor: &AuditActor,
    ) -> AppResult<Node> {
        validate_update_node_input(input)?;

        let existing = self.get_node(node_id).await?;
        let next_name = input.name.clone().unwrap_or_else(|| existing.name.clone());
        let next_hostname = input
            .hostname
            .clone()
            .unwrap_or_else(|| existing.hostname.clone());
        let next_tags = match &input.tags {
            Some(tags) => normalize_acl_tags(tags)?,
            None => existing.tags.clone(),
        };
        let next_tag_source = match &input.tags {
            Some(_) => node_tag_source_for_tags(next_tags.as_slice(), NodeTagSource::Admin),
            None => existing.tag_source,
        };

        let row = sqlx::query(
            r#"
            UPDATE nodes
            SET
                name = $2,
                hostname = $3,
                tags = $4,
                tag_source = $5,
                updated_at = now()
            WHERE id = $1
            RETURNING
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
            "#,
        )
        .bind(u64_to_i64(node_id)?)
        .bind(&next_name)
        .bind(&next_hostname)
        .bind(serde_json::to_value(&next_tags)?)
        .bind(next_tag_source.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_write_error)?;

        let node = match row {
            Some(row) => map_node_row(row)?,
            None => return Err(AppError::NotFound(format!("node {node_id}"))),
        };

        self.record_audit_event(
            AuditEventKind::NodeUpdated,
            actor,
            &format!("node/{}", node.id),
        )
        .await?;
        self.notify_control_change().await;

        Ok(node)
    }

    pub async fn register_node_with_auth_key(
        &self,
        input: &RegisterNodeInput,
    ) -> AppResult<NodeRegistration> {
        validate_register_node_input(input)?;

        let mut tx = self.pool.begin().await?;
        let auth_key = self.authenticate_auth_key(&mut tx, &input.auth_key).await?;
        if !input.tags.is_empty() {
            return Err(AppError::InvalidRequest(
                "registration tags must be defined on the auth key, not supplied by the caller"
                    .to_string(),
            ));
        }
        let (ipv4, ipv6) = self.allocate_node_addresses(&mut tx, None, None).await?;
        let session_token = generate_node_session_secret();
        let session_expires_at_unix_secs =
            next_session_expiry_unix_secs(self.network.node_session_ttl_secs)?;
        let last_seen_unix_secs = now_unix_secs()?;

        let node = self
            .insert_node(
                &mut tx,
                InsertNode {
                    stable_id: Uuid::new_v4().to_string(),
                    name: input.name.clone().unwrap_or_else(|| input.hostname.clone()),
                    hostname: input.hostname.clone(),
                    auth_key_id: Some(auth_key.id.clone()),
                    principal_id: None,
                    session_secret_hash: Some(hash_secret(&session_token)),
                    session_expires_at_unix_secs: Some(session_expires_at_unix_secs),
                    ipv4,
                    ipv6,
                    status: NodeStatus::Online,
                    tags: auth_key.tags.clone(),
                    tag_source: node_tag_source_for_tags(
                        auth_key.tags.as_slice(),
                        NodeTagSource::AuthKey,
                    ),
                    last_seen_unix_secs: Some(last_seen_unix_secs),
                },
            )
            .await?;

        let update_state = if auth_key.reusable {
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
        .bind(&auth_key.id)
        .bind(update_state.as_str())
        .execute(&mut *tx)
        .await?;

        let actor = AuditActor {
            subject: format!("auth_key:{}", auth_key.id),
            mechanism: "auth_key".to_string(),
        };
        self.record_audit_event_tx(
            &mut tx,
            AuditEventKind::NodeRegistered,
            &actor,
            &format!("node/{}", node.id),
        )
        .await?;

        tx.commit().await?;
        self.notify_control_change().await;

        let map = self.build_node_map(node.id).await?;

        Ok(NodeRegistration {
            node,
            session_token,
            map,
        })
    }

    pub async fn heartbeat_node_session(
        &self,
        node_id: u64,
        session_token: &str,
    ) -> AppResult<NodeHeartbeat> {
        self.authenticate_node_session(node_id, session_token)
            .await?;

        let observed_at = now_unix_secs()?;
        let session_expires_at_unix_secs =
            next_session_expiry_unix_secs(self.network.node_session_ttl_secs)?;
        let row = sqlx::query(
            r#"
            UPDATE nodes
            SET
                last_seen_unix_secs = $2,
                status = $3,
                session_expires_at = to_timestamp($4),
                updated_at = now()
            WHERE id = $1
            RETURNING
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
            "#,
        )
        .bind(u64_to_i64(node_id)?)
        .bind(u64_to_i64(observed_at)?)
        .bind(NodeStatus::Online.as_str())
        .bind(session_expires_at_unix_secs as f64)
        .fetch_one(&self.pool)
        .await?;

        self.notify_control_change().await;

        Ok(NodeHeartbeat {
            node: map_node_row(row)?,
            observed_at_unix_secs: observed_at,
        })
    }

    pub async fn sync_node_map(&self, node_id: u64, session_token: &str) -> AppResult<NodeMap> {
        self.authenticate_node_session(node_id, session_token)
            .await?;

        let observed_at = now_unix_secs()?;
        let session_expires_at_unix_secs =
            next_session_expiry_unix_secs(self.network.node_session_ttl_secs)?;
        sqlx::query(
            r#"
            UPDATE nodes
            SET
                last_seen_unix_secs = $2,
                status = $3,
                last_sync_at = now(),
                session_expires_at = to_timestamp($4),
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(u64_to_i64(node_id)?)
        .bind(u64_to_i64(observed_at)?)
        .bind(NodeStatus::Online.as_str())
        .bind(session_expires_at_unix_secs as f64)
        .execute(&self.pool)
        .await?;

        self.notify_control_change().await;

        self.build_node_map(node_id).await
    }

    pub async fn list_routes(&self) -> AppResult<Vec<Route>> {
        let rows = sqlx::query(
            r#"
            SELECT id, node_id, prefix, advertised, approval, approved_by_policy, is_exit_node
            FROM routes
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(map_route_row).collect()
    }

    pub async fn create_route(
        &self,
        input: &CreateRouteInput,
        actor: &AuditActor,
    ) -> AppResult<Route> {
        validate_create_route_input(input)?;
        let node = self.get_node(input.node_id).await?;
        if node.status == NodeStatus::Disabled {
            return Err(AppError::InvalidRequest(
                "cannot create routes for disabled nodes".to_string(),
            ));
        }

        let principal = self.load_route_principal(node.principal_id).await?;
        let policy = self.load_policy().await?;
        let pending_route = Route {
            id: 0,
            node_id: input.node_id,
            prefix: input.prefix.clone(),
            advertised: input.advertised,
            approval: RouteApproval::Pending,
            approved_by_policy: false,
            is_exit_node: input.is_exit_node,
        };
        let approved_by_policy =
            policy.auto_approves_route(&node, principal.as_ref(), &pending_route)?;
        let approval = if approved_by_policy {
            RouteApproval::Approved
        } else {
            RouteApproval::Pending
        };

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
            RETURNING id, node_id, prefix, advertised, approval, approved_by_policy, is_exit_node
            "#,
        )
        .bind(u64_to_i64(input.node_id)?)
        .bind(&input.prefix)
        .bind(input.advertised)
        .bind(approval.as_str())
        .bind(approved_by_policy)
        .bind(input.is_exit_node)
        .fetch_one(&self.pool)
        .await
        .map_err(map_database_write_error)?;

        let route = map_route_row(row)?;
        self.record_audit_event(
            AuditEventKind::RouteCreated,
            actor,
            &format!("route/{}", route.id),
        )
        .await?;
        self.notify_control_change().await;

        Ok(route)
    }

    pub async fn set_route_approval(
        &self,
        route_id: u64,
        approval: RouteApproval,
        actor: &AuditActor,
    ) -> AppResult<Route> {
        let target = sqlx::query(
            r#"
            SELECT id, node_id, prefix, advertised, approval, approved_by_policy, is_exit_node
            FROM routes
            WHERE id = $1
            "#,
        )
        .bind(u64_to_i64(route_id)?)
        .fetch_optional(&self.pool)
        .await?;

        let target_route = match target {
            Some(row) => map_route_row(row)?,
            None => return Err(AppError::NotFound(format!("route {route_id}"))),
        };

        let rows = if target_route.is_exit_node
            || matches!(target_route.prefix.as_str(), "0.0.0.0/0" | "::/0")
        {
            sqlx::query(
                r#"
                UPDATE routes
                SET approval = $2, approved_by_policy = FALSE, updated_at = now()
                WHERE node_id = $1 AND (is_exit_node = TRUE OR prefix IN ('0.0.0.0/0', '::/0'))
                RETURNING id, node_id, prefix, advertised, approval, approved_by_policy, is_exit_node
                "#,
            )
            .bind(u64_to_i64(target_route.node_id)?)
            .bind(approval.as_str())
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                UPDATE routes
                SET approval = $2, approved_by_policy = FALSE, updated_at = now()
                WHERE id = $1
                RETURNING id, node_id, prefix, advertised, approval, approved_by_policy, is_exit_node
                "#,
            )
            .bind(u64_to_i64(route_id)?)
            .bind(approval.as_str())
            .fetch_all(&self.pool)
            .await?
        };

        let route = rows
            .into_iter()
            .map(map_route_row)
            .collect::<AppResult<Vec<_>>>()?
            .into_iter()
            .find(|route| route.id == route_id)
            .ok_or_else(|| AppError::NotFound(format!("route {route_id}")))?;

        self.record_audit_event(
            match approval {
                RouteApproval::Approved => AuditEventKind::RouteApproved,
                RouteApproval::Rejected => AuditEventKind::RouteRejected,
                RouteApproval::Pending => AuditEventKind::RouteCreated,
            },
            actor,
            &format!("route/{}", route.id),
        )
        .await?;
        self.notify_control_change().await;

        Ok(route)
    }

    pub async fn disable_node(&self, node_id: u64, actor: &AuditActor) -> AppResult<Node> {
        let row = sqlx::query(
            r#"
            UPDATE nodes
            SET status = $2, updated_at = now()
            WHERE id = $1
            RETURNING
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
            "#,
        )
        .bind(u64_to_i64(node_id)?)
        .bind(NodeStatus::Disabled.as_str())
        .fetch_optional(&self.pool)
        .await?;

        let node = match row {
            Some(row) => map_node_row(row)?,
            None => return Err(AppError::NotFound(format!("node {node_id}"))),
        };

        self.record_audit_event(
            AuditEventKind::NodeDisabled,
            actor,
            &format!("node/{}", node.id),
        )
        .await?;
        self.notify_control_change().await;

        Ok(node)
    }

    pub async fn list_auth_keys(&self) -> AppResult<Vec<AuthKey>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                description,
                tags,
                reusable,
                ephemeral,
                state,
                usage_count,
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix_secs,
                EXTRACT(EPOCH FROM created_at)::bigint AS created_at_unix_secs,
                EXTRACT(EPOCH FROM last_used_at)::bigint AS last_used_at_unix_secs,
                EXTRACT(EPOCH FROM revoked_at)::bigint AS revoked_at_unix_secs
            FROM auth_keys
            ORDER BY created_at DESC, id DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(map_auth_key_row).collect()
    }

    pub async fn count_active_auth_keys(&self) -> AppResult<u64> {
        let count =
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM auth_keys WHERE state = 'active' AND (expires_at IS NULL OR expires_at > now())",
            )
            .fetch_one(&self.pool)
            .await?;
        i64_to_u64(count)
    }

    pub async fn count_routes(&self) -> AppResult<u64> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM routes")
            .fetch_one(&self.pool)
            .await?;
        i64_to_u64(count)
    }

    pub async fn list_principals(&self) -> AppResult<Vec<Principal>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                provider,
                issuer,
                subject,
                login_name,
                display_name,
                email,
                groups,
                EXTRACT(EPOCH FROM created_at)::bigint AS created_at_unix_secs
            FROM principals
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(map_principal_row).collect()
    }

    pub(super) async fn load_route_principal(
        &self,
        principal_id: Option<u64>,
    ) -> AppResult<Option<Principal>> {
        let Some(principal_id) = principal_id else {
            return Ok(None);
        };

        let row = sqlx::query(
            r#"
            SELECT
                id,
                provider,
                issuer,
                subject,
                login_name,
                display_name,
                email,
                groups,
                EXTRACT(EPOCH FROM created_at)::bigint AS created_at_unix_secs
            FROM principals
            WHERE id = $1
            "#,
        )
        .bind(u64_to_i64(principal_id)?)
        .fetch_optional(&self.pool)
        .await?;

        row.map(map_principal_row).transpose()
    }

    async fn reconcile_policy_route_approvals(&self, policy: &AclPolicy) -> AppResult<bool> {
        let routes = self.list_routes().await?;
        if routes.is_empty() {
            return Ok(false);
        }

        let nodes = self.list_nodes().await?;
        let principals = self.list_principals().await?;
        let updates = plan_route_policy_reconciliation(policy, &routes, &nodes, &principals)?;
        if updates.is_empty() {
            return Ok(false);
        }

        let mut tx = self.pool.begin().await?;
        for update in &updates {
            sqlx::query(
                r#"
                UPDATE routes
                SET approval = $2, approved_by_policy = $3, updated_at = now()
                WHERE id = $1
                "#,
            )
            .bind(u64_to_i64(update.route_id)?)
            .bind(update.approval.as_str())
            .bind(update.approved_by_policy)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(true)
    }

    pub async fn create_auth_key(
        &self,
        input: &CreateAuthKeyInput,
        actor: &AuditActor,
    ) -> AppResult<IssuedAuthKey> {
        validate_create_auth_key_input(input)?;

        let key = generate_auth_key_secret();
        let row = sqlx::query(
            r#"
            INSERT INTO auth_keys (
                id,
                secret_hash,
                description,
                tags,
                reusable,
                ephemeral,
                state,
                expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8))
            RETURNING
                id,
                description,
                tags,
                reusable,
                ephemeral,
                state,
                usage_count,
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix_secs,
                EXTRACT(EPOCH FROM created_at)::bigint AS created_at_unix_secs,
                EXTRACT(EPOCH FROM last_used_at)::bigint AS last_used_at_unix_secs,
                EXTRACT(EPOCH FROM revoked_at)::bigint AS revoked_at_unix_secs
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(hash_secret(&key))
        .bind(input.description.as_deref())
        .bind(serde_json::to_value(normalize_acl_tags(&input.tags)?)?)
        .bind(input.reusable)
        .bind(input.ephemeral)
        .bind(AuthKeyState::Active.as_str())
        .bind(input.expires_at_unix_secs.map(|value| value as f64))
        .fetch_one(&self.pool)
        .await
        .map_err(map_database_write_error)?;

        let auth_key = map_auth_key_row(row)?;
        self.record_audit_event(
            AuditEventKind::AuthKeyCreated,
            actor,
            &format!("auth_key/{}", auth_key.id),
        )
        .await?;

        Ok(IssuedAuthKey { auth_key, key })
    }

    pub async fn revoke_auth_key(
        &self,
        auth_key_id: &str,
        actor: &AuditActor,
    ) -> AppResult<AuthKey> {
        if auth_key_id.trim().is_empty() {
            return Err(AppError::InvalidRequest(
                "auth key identifier must not be empty".to_string(),
            ));
        }

        let row = sqlx::query(
            r#"
            UPDATE auth_keys
            SET state = $2, revoked_at = now()
            WHERE id = $1 AND state <> $2
            RETURNING
                id,
                description,
                tags,
                reusable,
                ephemeral,
                state,
                usage_count,
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix_secs,
                EXTRACT(EPOCH FROM created_at)::bigint AS created_at_unix_secs,
                EXTRACT(EPOCH FROM last_used_at)::bigint AS last_used_at_unix_secs,
                EXTRACT(EPOCH FROM revoked_at)::bigint AS revoked_at_unix_secs
            "#,
        )
        .bind(auth_key_id)
        .bind(AuthKeyState::Revoked.as_str())
        .fetch_optional(&self.pool)
        .await?;

        let auth_key = match row {
            Some(row) => map_auth_key_row(row)?,
            None => return Err(AppError::NotFound(format!("auth key {auth_key_id}"))),
        };

        self.record_audit_event(
            AuditEventKind::AuthKeyRevoked,
            actor,
            &format!("auth_key/{}", auth_key.id),
        )
        .await?;

        Ok(auth_key)
    }

    pub async fn load_policy(&self) -> AppResult<AclPolicy> {
        let row = sqlx::query("SELECT policy FROM control_plane_state WHERE id = $1")
            .bind(CONTROL_PLANE_STATE_ID)
            .fetch_one(&self.pool)
            .await?;

        let value = row.get::<serde_json::Value, _>("policy");
        let policy = serde_json::from_value::<AclPolicy>(value)?;
        policy.validate()?;
        Ok(policy)
    }

    pub async fn save_policy(
        &self,
        policy: &AclPolicy,
        actor: &AuditActor,
    ) -> AppResult<AclPolicy> {
        policy.validate()?;

        sqlx::query(
            r#"
            INSERT INTO control_plane_state (id, policy, dns)
            VALUES ($1, $2, '{"magic_dns":false,"base_domain":null,"nameservers":[],"search_domains":[]}'::jsonb)
            ON CONFLICT (id)
            DO UPDATE SET policy = EXCLUDED.policy, updated_at = now()
            "#,
        )
        .bind(CONTROL_PLANE_STATE_ID)
        .bind(serde_json::to_value(policy)?)
        .execute(&self.pool)
        .await?;

        let _ = self.reconcile_policy_route_approvals(policy).await?;

        self.record_audit_event(AuditEventKind::PolicyUpdated, actor, "policy/global")
            .await?;
        self.clear_ssh_check_approvals().await?;
        self.notify_control_change().await;

        Ok(policy.clone())
    }

    pub async fn load_dns_config(&self) -> AppResult<DnsConfig> {
        let row = sqlx::query("SELECT dns FROM control_plane_state WHERE id = $1")
            .bind(CONTROL_PLANE_STATE_ID)
            .fetch_one(&self.pool)
            .await?;

        let value = row.get::<serde_json::Value, _>("dns");
        let dns = serde_json::from_value::<DnsConfig>(value)?;
        dns.validate()?;
        Ok(dns)
    }

    pub async fn save_dns_config(
        &self,
        dns: &DnsConfig,
        actor: &AuditActor,
    ) -> AppResult<DnsConfig> {
        dns.validate()?;

        sqlx::query(
            r#"
            INSERT INTO control_plane_state (id, policy, dns)
            VALUES ($1, '{"groups":[],"rules":[]}'::jsonb, $2)
            ON CONFLICT (id)
            DO UPDATE SET dns = EXCLUDED.dns, updated_at = now()
            "#,
        )
        .bind(CONTROL_PLANE_STATE_ID)
        .bind(serde_json::to_value(dns)?)
        .execute(&self.pool)
        .await?;

        self.record_audit_event(AuditEventKind::DnsUpdated, actor, "dns/global")
            .await?;
        self.notify_control_change().await;

        Ok(dns.clone())
    }

    pub async fn list_audit_events(&self, limit: u32) -> AppResult<Vec<AuditEvent>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                kind,
                actor_subject,
                actor_mechanism,
                target,
                EXTRACT(EPOCH FROM occurred_at)::bigint AS occurred_at_unix_secs
            FROM audit_events
            ORDER BY occurred_at DESC, id DESC
            LIMIT $1
            "#,
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(map_audit_event_row).collect()
    }

    pub async fn count_audit_events(&self) -> AppResult<u64> {
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&self.pool)
            .await?;
        i64_to_u64(count)
    }

    pub async fn export_backup(&self) -> AppResult<BackupSnapshot> {
        Ok(BackupSnapshot {
            format_version: BACKUP_FORMAT_VERSION,
            generated_at_unix_secs: now_unix_secs()?,
            principals: self.list_principals().await?,
            nodes: self.list_nodes().await?,
            auth_keys: self.list_backup_auth_keys().await?,
            policy: self.load_policy().await?,
            dns: self.load_dns_config().await?,
            routes: self.list_routes().await?,
            audit_events: self.list_audit_events(10_000).await?,
        })
    }

    pub async fn restore_backup(
        &self,
        snapshot: &BackupSnapshot,
        actor: &AuditActor,
    ) -> AppResult<BackupRestoreResult> {
        if snapshot.format_version == 0 || snapshot.format_version > BACKUP_FORMAT_VERSION {
            return Err(AppError::InvalidRequest(format!(
                "unsupported backup format version: {}",
                snapshot.format_version
            )));
        }

        snapshot.policy.validate()?;
        snapshot.dns.validate()?;
        for route in &snapshot.routes {
            route.validate()?;
        }

        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "TRUNCATE TABLE audit_events, routes, node_control_state, oidc_auth_requests, nodes, principals, auth_keys RESTART IDENTITY",
        )
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            r#"
            INSERT INTO control_plane_state (id, policy, dns)
            VALUES ($1, $2, $3)
            ON CONFLICT (id)
            DO UPDATE SET policy = EXCLUDED.policy, dns = EXCLUDED.dns, updated_at = now()
            "#,
        )
        .bind(CONTROL_PLANE_STATE_ID)
        .bind(serde_json::to_value(&snapshot.policy)?)
        .bind(serde_json::to_value(&snapshot.dns)?)
        .execute(&mut *tx)
        .await?;

        for backup_auth_key in &snapshot.auth_keys {
            let auth_key = &backup_auth_key.auth_key;
            sqlx::query(
                r#"
                INSERT INTO auth_keys (
                    id,
                    secret_hash,
                    description,
                    tags,
                    reusable,
                    ephemeral,
                    state,
                    usage_count,
                    expires_at,
                    created_at,
                    last_used_at,
                    revoked_at
                )
                VALUES (
                    $1,
                    $2,
                    $3,
                    $4,
                    $5,
                    $6,
                    $7,
                    $8,
                    to_timestamp($9),
                    to_timestamp($10),
                    to_timestamp($11),
                    to_timestamp($12)
                )
                "#,
            )
            .bind(&auth_key.id)
            .bind(&backup_auth_key.secret_hash)
            .bind(auth_key.description.as_deref())
            .bind(serde_json::to_value(&auth_key.tags)?)
            .bind(auth_key.reusable)
            .bind(auth_key.ephemeral)
            .bind(auth_key.state.as_str())
            .bind(u64_to_i64(auth_key.usage_count)?)
            .bind(auth_key.expires_at_unix_secs.map(|value| value as f64))
            .bind(auth_key.created_at_unix_secs as f64)
            .bind(auth_key.last_used_at_unix_secs.map(|value| value as f64))
            .bind(auth_key.revoked_at_unix_secs.map(|value| value as f64))
            .execute(&mut *tx)
            .await
            .map_err(map_database_write_error)?;
        }

        let mut max_principal_id = 0_u64;
        for principal in &snapshot.principals {
            sqlx::query(
                r#"
                INSERT INTO principals (
                    id,
                    provider,
                    issuer,
                    subject,
                    login_name,
                    display_name,
                    email,
                    groups,
                    created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, to_timestamp($9))
                "#,
            )
            .bind(u64_to_i64(principal.id)?)
            .bind(&principal.provider)
            .bind(&principal.issuer)
            .bind(&principal.subject)
            .bind(&principal.login_name)
            .bind(&principal.display_name)
            .bind(&principal.email)
            .bind(serde_json::to_value(&principal.groups)?)
            .bind(principal.created_at_unix_secs as f64)
            .execute(&mut *tx)
            .await
            .map_err(map_database_write_error)?;

            max_principal_id = max_principal_id.max(principal.id);
        }

        reset_principals_sequence(&mut tx, max_principal_id, !snapshot.principals.is_empty())
            .await?;

        let mut max_node_id = 0_u64;
        for node in &snapshot.nodes {
            if node.name.trim().is_empty() || node.hostname.trim().is_empty() {
                return Err(AppError::InvalidRequest(
                    "backup contains node entries with empty name or hostname".to_string(),
                ));
            }

            sqlx::query(
                r#"
                INSERT INTO nodes (
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
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                "#,
            )
            .bind(u64_to_i64(node.id)?)
            .bind(&node.stable_id)
            .bind(&node.name)
            .bind(&node.hostname)
            .bind(&node.auth_key_id)
            .bind(node.principal_id.map(u64_to_i64).transpose()?)
            .bind(&node.ipv4)
            .bind(&node.ipv6)
            .bind(restored_node_status(&node.status).as_str())
            .bind(serde_json::to_value(&node.tags)?)
            .bind(node_tag_source_for_tags(node.tags.as_slice(), node.tag_source).as_str())
            .bind(node.last_seen_unix_secs.map(u64_to_i64).transpose()?)
            .execute(&mut *tx)
            .await
            .map_err(map_database_write_error)?;

            max_node_id = max_node_id.max(node.id);
        }

        reset_nodes_sequence(&mut tx, max_node_id, !snapshot.nodes.is_empty()).await?;

        let mut max_route_id = 0_u64;
        for route in &snapshot.routes {
            sqlx::query(
                r#"
                INSERT INTO routes (
                    id,
                    node_id,
                    prefix,
                    advertised,
                    approval,
                    approved_by_policy,
                    is_exit_node
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                "#,
            )
            .bind(u64_to_i64(route.id)?)
            .bind(u64_to_i64(route.node_id)?)
            .bind(&route.prefix)
            .bind(route.advertised)
            .bind(route.approval.as_str())
            .bind(route.approved_by_policy)
            .bind(route.is_exit_node)
            .execute(&mut *tx)
            .await
            .map_err(map_database_write_error)?;

            max_route_id = max_route_id.max(route.id);
        }

        reset_routes_sequence(&mut tx, max_route_id, !snapshot.routes.is_empty()).await?;

        for event in &snapshot.audit_events {
            sqlx::query(
                r#"
                INSERT INTO audit_events (
                    id,
                    kind,
                    actor_subject,
                    actor_mechanism,
                    target,
                    occurred_at
                )
                VALUES ($1, $2, $3, $4, $5, to_timestamp($6))
                "#,
            )
            .bind(&event.id)
            .bind(event.kind.as_str())
            .bind(&event.actor.subject)
            .bind(&event.actor.mechanism)
            .bind(&event.target)
            .bind(event.occurred_at_unix_secs as f64)
            .execute(&mut *tx)
            .await
            .map_err(map_database_write_error)?;
        }

        sqlx::query(
            r#"
            INSERT INTO audit_events (
                id,
                kind,
                actor_subject,
                actor_mechanism,
                target
            )
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(AuditEventKind::BackupRestored.as_str())
        .bind(&actor.subject)
        .bind(&actor.mechanism)
        .bind("backup/global")
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        self.notify_control_change().await;

        Ok(BackupRestoreResult {
            restored_principals: snapshot.principals.len() as u64,
            restored_nodes: snapshot.nodes.len() as u64,
            restored_auth_keys: snapshot.auth_keys.len() as u64,
            restored_routes: snapshot.routes.len() as u64,
            restored_audit_events: snapshot.audit_events.len() as u64,
        })
    }

    pub(super) async fn insert_node(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        node: InsertNode,
    ) -> AppResult<Node> {
        let row = sqlx::query(
            r#"
            INSERT INTO nodes (
                stable_id,
                name,
                hostname,
                auth_key_id,
                principal_id,
                session_secret_hash,
                session_expires_at,
                ipv4,
                ipv6,
                status,
                tags,
                tag_source,
                last_seen_unix_secs
            )
            VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7), $8, $9, $10, $11, $12, $13)
            RETURNING
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
            "#,
        )
        .bind(&node.stable_id)
        .bind(&node.name)
        .bind(&node.hostname)
        .bind(&node.auth_key_id)
        .bind(node.principal_id.map(u64_to_i64).transpose()?)
        .bind(&node.session_secret_hash)
        .bind(node.session_expires_at_unix_secs.map(|value| value as f64))
        .bind(&node.ipv4)
        .bind(&node.ipv6)
        .bind(node.status.as_str())
        .bind(serde_json::to_value(&node.tags)?)
        .bind(node.tag_source.as_str())
        .bind(node.last_seen_unix_secs.map(u64_to_i64).transpose()?)
        .fetch_one(&mut **tx)
        .await
        .map_err(map_database_write_error)?;

        map_node_row(row)
    }

    pub(super) async fn allocate_node_addresses(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        requested_ipv4: Option<&str>,
        requested_ipv6: Option<&str>,
    ) -> AppResult<(Option<String>, Option<String>)> {
        // Serialize tailnet address allocation within the current transaction so
        // concurrent registrations cannot observe the same free address set.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(7_240_539_422_875_577_456_i64)
            .execute(&mut **tx)
            .await?;

        let rows = sqlx::query("SELECT ipv4, ipv6 FROM nodes")
            .fetch_all(&mut **tx)
            .await?;

        let mut used_ipv4 = std::collections::BTreeSet::new();
        let mut used_ipv6 = std::collections::BTreeSet::new();

        for row in rows {
            if let Some(ipv4) = row.get::<Option<String>, _>("ipv4") {
                used_ipv4.insert(ipv4);
            }

            if let Some(ipv6) = row.get::<Option<String>, _>("ipv6") {
                used_ipv6.insert(ipv6);
            }
        }

        let ipv4 = match requested_ipv4 {
            Some(ipv4) => {
                parse_ipv4(ipv4)?;
                if used_ipv4.contains(ipv4) {
                    return Err(AppError::Conflict(format!(
                        "IPv4 address already allocated: {ipv4}"
                    )));
                }
                Some(ipv4.to_string())
            }
            None => Some(allocate_next_ipv4(
                &self.network.tailnet_ipv4_range,
                &used_ipv4,
            )?),
        };

        let ipv6 = match requested_ipv6 {
            Some(ipv6) => {
                parse_ipv6(ipv6)?;
                if used_ipv6.contains(ipv6) {
                    return Err(AppError::Conflict(format!(
                        "IPv6 address already allocated: {ipv6}"
                    )));
                }
                Some(ipv6.to_string())
            }
            None => Some(allocate_next_ipv6(
                &self.network.tailnet_ipv6_range,
                &used_ipv6,
            )?),
        };

        Ok((ipv4, ipv6))
    }

    async fn build_node_map(&self, node_id: u64) -> AppResult<NodeMap> {
        let generated_at = now_unix_secs()?;
        let all_nodes = self
            .list_nodes()
            .await?
            .into_iter()
            .map(|node| {
                effective_node_status(node, generated_at, self.network.node_online_window_secs)
            })
            .collect::<Vec<_>>();
        let mut node_statuses = std::collections::HashMap::with_capacity(all_nodes.len());
        let mut self_node = None;
        let mut peers = Vec::new();
        for node in all_nodes {
            node_statuses.insert(node.id, node.status.clone());
            if node.id == node_id {
                self_node = Some(node);
            } else if node.status != NodeStatus::Disabled {
                peers.push(node);
            }
        }
        let self_node = self_node.ok_or_else(|| AppError::NotFound(format!("node {node_id}")))?;
        let policy = self.load_policy().await?;
        let routes = self
            .list_approved_routes()
            .await?
            .into_iter()
            .filter(|route| matches!(node_statuses.get(&route.node_id), Some(NodeStatus::Online)))
            .collect::<Vec<_>>();
        let evaluated_policy = policy.evaluate_for_node(
            &self_node,
            &std::iter::once(self_node.clone())
                .chain(peers.clone())
                .collect::<Vec<_>>(),
            &routes,
        )?;
        let peers = peers
            .into_iter()
            .filter(|peer| evaluated_policy.visible_peer_ids.contains(&peer.id))
            .collect();
        let routes = routes
            .into_iter()
            .filter(|route| {
                route.node_id == self_node.id
                    || evaluated_policy.visible_route_ids.contains(&route.id)
            })
            .collect::<Vec<_>>();

        Ok(NodeMap {
            self_node,
            peers,
            policy,
            dns: self.load_dns_config().await?,
            routes,
            generated_at_unix_secs: generated_at,
        })
    }

    pub(super) async fn authenticate_auth_key(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        auth_key: &str,
    ) -> AppResult<AuthKey> {
        let row = sqlx::query(
            r#"
            SELECT
                id,
                description,
                tags,
                reusable,
                ephemeral,
                state,
                usage_count,
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix_secs,
                EXTRACT(EPOCH FROM created_at)::bigint AS created_at_unix_secs,
                EXTRACT(EPOCH FROM last_used_at)::bigint AS last_used_at_unix_secs,
                EXTRACT(EPOCH FROM revoked_at)::bigint AS revoked_at_unix_secs
            FROM auth_keys
            WHERE
                secret_hash = $1
                AND state = 'active'
                AND (expires_at IS NULL OR expires_at > now())
            FOR UPDATE
            "#,
        )
        .bind(hash_secret(auth_key))
        .fetch_optional(&mut **tx)
        .await?;

        match row {
            Some(row) => map_auth_key_row(row),
            None => Err(AppError::Unauthorized(
                "invalid or expired auth key".to_string(),
            )),
        }
    }

    async fn authenticate_node_session(
        &self,
        node_id: u64,
        session_token: &str,
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
            WHERE
                id = $1
                AND session_secret_hash = $2
                AND status <> 'disabled'
                AND session_expires_at IS NOT NULL
                AND session_expires_at > now()
            "#,
        )
        .bind(u64_to_i64(node_id)?)
        .bind(hash_secret(session_token))
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => map_node_row(row),
            None => Err(AppError::Unauthorized(
                "invalid or expired node session token".to_string(),
            )),
        }
    }

    async fn list_approved_routes(&self) -> AppResult<Vec<Route>> {
        let rows = sqlx::query(
            r#"
            SELECT id, node_id, prefix, advertised, approval, approved_by_policy, is_exit_node
            FROM routes
            WHERE approval = 'approved' AND advertised = TRUE
            ORDER BY node_id ASC, id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(map_route_row).collect()
    }

    async fn list_backup_auth_keys(&self) -> AppResult<Vec<BackupAuthKey>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                secret_hash,
                description,
                tags,
                reusable,
                ephemeral,
                state,
                usage_count,
                EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_unix_secs,
                EXTRACT(EPOCH FROM created_at)::bigint AS created_at_unix_secs,
                EXTRACT(EPOCH FROM last_used_at)::bigint AS last_used_at_unix_secs,
                EXTRACT(EPOCH FROM revoked_at)::bigint AS revoked_at_unix_secs
            FROM auth_keys
            ORDER BY created_at DESC, id DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(map_backup_auth_key_row).collect()
    }

    pub(super) async fn record_audit_event(
        &self,
        kind: AuditEventKind,
        actor: &AuditActor,
        target: &str,
    ) -> AppResult<()> {
        let mut tx = self.pool.begin().await?;
        self.record_audit_event_tx(&mut tx, kind, actor, target)
            .await?;
        tx.commit().await?;

        Ok(())
    }

    pub(super) async fn record_audit_event_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        kind: AuditEventKind,
        actor: &AuditActor,
        target: &str,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            INSERT INTO audit_events (
                id,
                kind,
                actor_subject,
                actor_mechanism,
                target
            )
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(kind.as_str())
        .bind(&actor.subject)
        .bind(&actor.mechanism)
        .bind(target)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateNodeInput {
    pub name: String,
    pub hostname: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct UpdateNodeInput {
    pub name: Option<String>,
    pub hostname: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateAuthKeyInput {
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub reusable: bool,
    pub ephemeral: bool,
    pub expires_at_unix_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterNodeInput {
    pub auth_key: String,
    pub name: Option<String>,
    pub hostname: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateRouteInput {
    pub node_id: u64,
    pub prefix: String,
    pub advertised: bool,
    pub is_exit_node: bool,
}

#[derive(Debug, Clone)]
pub(super) struct InsertNode {
    pub(super) stable_id: String,
    pub(super) name: String,
    pub(super) hostname: String,
    pub(super) auth_key_id: Option<String>,
    pub(super) principal_id: Option<u64>,
    pub(super) session_secret_hash: Option<String>,
    pub(super) session_expires_at_unix_secs: Option<u64>,
    pub(super) ipv4: Option<String>,
    pub(super) ipv6: Option<String>,
    pub(super) status: NodeStatus,
    pub(super) tags: Vec<String>,
    pub(super) tag_source: NodeTagSource,
    pub(super) last_seen_unix_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoutePolicyApprovalUpdate {
    route_id: u64,
    approval: RouteApproval,
    approved_by_policy: bool,
}

fn plan_route_policy_reconciliation(
    policy: &AclPolicy,
    routes: &[Route],
    nodes: &[Node],
    principals: &[Principal],
) -> AppResult<Vec<RoutePolicyApprovalUpdate>> {
    let nodes_by_id = nodes
        .iter()
        .cloned()
        .map(|node| (node.id, node))
        .collect::<std::collections::BTreeMap<_, _>>();
    let principals_by_id = principals
        .iter()
        .cloned()
        .map(|principal| (principal.id, principal))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut updates = Vec::new();

    for route in routes {
        let node = nodes_by_id.get(&route.node_id).ok_or_else(|| {
            AppError::Bootstrap(format!(
                "route {} references missing node {}",
                route.id, route.node_id
            ))
        })?;
        let principal = node
            .principal_id
            .and_then(|principal_id| principals_by_id.get(&principal_id));
        let should_auto_approve = policy.auto_approves_route(node, principal, route)?;

        match (
            should_auto_approve,
            &route.approval,
            route.approved_by_policy,
        ) {
            (true, RouteApproval::Pending, _) => updates.push(RoutePolicyApprovalUpdate {
                route_id: route.id,
                approval: RouteApproval::Approved,
                approved_by_policy: true,
            }),
            (true, RouteApproval::Approved, true) => {}
            (true, _, false) => {}
            (true, RouteApproval::Rejected, true) => updates.push(RoutePolicyApprovalUpdate {
                route_id: route.id,
                approval: RouteApproval::Approved,
                approved_by_policy: true,
            }),
            (false, _, true) => updates.push(RoutePolicyApprovalUpdate {
                route_id: route.id,
                approval: RouteApproval::Pending,
                approved_by_policy: false,
            }),
            (false, _, false) => {}
        }
    }

    Ok(updates)
}

fn validate_create_node_input(input: &CreateNodeInput) -> AppResult<()> {
    if input.name.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "node name must not be empty".to_string(),
        ));
    }

    if input.hostname.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "node hostname must not be empty".to_string(),
        ));
    }

    normalize_acl_tags(&input.tags)?;

    Ok(())
}

fn validate_update_node_input(input: &UpdateNodeInput) -> AppResult<()> {
    if input
        .name
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AppError::InvalidRequest(
            "node name must not be empty when provided".to_string(),
        ));
    }

    if input
        .hostname
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AppError::InvalidRequest(
            "node hostname must not be empty when provided".to_string(),
        ));
    }

    if let Some(tags) = &input.tags {
        normalize_acl_tags(tags)?;
    }

    Ok(())
}

fn validate_create_auth_key_input(input: &CreateAuthKeyInput) -> AppResult<()> {
    if input
        .description
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AppError::InvalidRequest(
            "auth key description must not be empty".to_string(),
        ));
    }

    normalize_acl_tags(&input.tags)?;
    Ok(())
}

fn validate_register_node_input(input: &RegisterNodeInput) -> AppResult<()> {
    if input.auth_key.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "auth key must not be empty".to_string(),
        ));
    }

    if input.hostname.trim().is_empty() {
        return Err(AppError::InvalidRequest(
            "node hostname must not be empty".to_string(),
        ));
    }

    if input
        .name
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(AppError::InvalidRequest(
            "node name must not be empty when provided".to_string(),
        ));
    }

    normalize_acl_tags(&input.tags)?;

    Ok(())
}

fn validate_create_route_input(input: &CreateRouteInput) -> AppResult<()> {
    if input.node_id == 0 {
        return Err(AppError::InvalidRequest(
            "route node_id must be greater than zero".to_string(),
        ));
    }

    validate_route_prefix(&input.prefix)?;

    Ok(())
}

fn emit_local_control_change(control_updates: &watch::Sender<u64>) {
    let next = (*control_updates.borrow()).wrapping_add(1);
    let _ = control_updates.send_replace(next);
}

fn apply_remote_control_notification(
    control_updates: &watch::Sender<u64>,
    local_instance_id: &str,
    payload: &str,
) {
    if payload == local_instance_id {
        return;
    }

    emit_local_control_change(control_updates);
}

fn node_tag_source_for_tags(tags: &[String], source: NodeTagSource) -> NodeTagSource {
    if tags.is_empty() {
        NodeTagSource::None
    } else {
        source
    }
}

pub(super) fn map_node_row(row: sqlx::postgres::PgRow) -> AppResult<Node> {
    let id = row.get::<i64, _>("id");
    let status = row.get::<String, _>("status");
    let tags_value = row.get::<serde_json::Value, _>("tags");
    let tags = serde_json::from_value::<Vec<String>>(tags_value)?;
    let tag_source = row.get::<String, _>("tag_source");

    Ok(Node {
        id: i64_to_u64(id)?,
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
    })
}

pub(super) fn map_admin_node_row(
    row: sqlx::postgres::PgRow,
    now_unix_secs: u64,
    online_window_secs: u64,
) -> AppResult<Node> {
    let session_expires_at_unix_secs = row
        .get::<Option<i64>, _>("session_expires_at_unix_secs")
        .map(i64_to_u64)
        .transpose()?;
    let mut node = map_node_row(row)?;
    node.status = effective_admin_node_status(
        node.status.clone(),
        node.last_seen_unix_secs,
        session_expires_at_unix_secs,
        now_unix_secs,
        online_window_secs,
    );
    Ok(node)
}

pub(super) fn map_principal_row(row: sqlx::postgres::PgRow) -> AppResult<Principal> {
    Ok(Principal {
        id: i64_to_u64(row.get::<i64, _>("id"))?,
        provider: row.get("provider"),
        issuer: row.get("issuer"),
        subject: row.get("subject"),
        login_name: row.get("login_name"),
        display_name: row.get("display_name"),
        email: row.get("email"),
        groups: serde_json::from_value(row.get::<serde_json::Value, _>("groups"))?,
        created_at_unix_secs: i64_to_u64(row.get::<i64, _>("created_at_unix_secs"))?,
    })
}

pub(super) fn map_route_row(row: sqlx::postgres::PgRow) -> AppResult<Route> {
    let approval = row.get::<String, _>("approval");

    Ok(Route {
        id: i64_to_u64(row.get::<i64, _>("id"))?,
        node_id: i64_to_u64(row.get::<i64, _>("node_id"))?,
        prefix: row.get("prefix"),
        advertised: row.get("advertised"),
        approval: RouteApproval::parse(&approval).ok_or_else(|| {
            AppError::Bootstrap(format!(
                "unsupported route approval in database: {approval}"
            ))
        })?,
        approved_by_policy: row.get("approved_by_policy"),
        is_exit_node: row.get("is_exit_node"),
    })
}

fn map_auth_key_row(row: sqlx::postgres::PgRow) -> AppResult<AuthKey> {
    let state = row.get::<String, _>("state");
    let tags = serde_json::from_value::<Vec<String>>(row.get::<serde_json::Value, _>("tags"))?;

    Ok(AuthKey {
        id: row.get("id"),
        description: row.get("description"),
        tags,
        reusable: row.get("reusable"),
        ephemeral: row.get("ephemeral"),
        expires_at_unix_secs: row
            .get::<Option<i64>, _>("expires_at_unix_secs")
            .map(i64_to_u64)
            .transpose()?,
        created_at_unix_secs: i64_to_u64(row.get::<i64, _>("created_at_unix_secs"))?,
        last_used_at_unix_secs: row
            .get::<Option<i64>, _>("last_used_at_unix_secs")
            .map(i64_to_u64)
            .transpose()?,
        revoked_at_unix_secs: row
            .get::<Option<i64>, _>("revoked_at_unix_secs")
            .map(i64_to_u64)
            .transpose()?,
        usage_count: i64_to_u64(row.get::<i64, _>("usage_count"))?,
        state: AuthKeyState::parse(&state).ok_or_else(|| {
            AppError::Bootstrap(format!("unsupported auth key state in database: {state}"))
        })?,
    })
}

fn map_backup_auth_key_row(row: sqlx::postgres::PgRow) -> AppResult<BackupAuthKey> {
    let state = row.get::<String, _>("state");
    let tags = serde_json::from_value::<Vec<String>>(row.get::<serde_json::Value, _>("tags"))?;

    Ok(BackupAuthKey {
        auth_key: AuthKey {
            id: row.get("id"),
            description: row.get("description"),
            tags,
            reusable: row.get("reusable"),
            ephemeral: row.get("ephemeral"),
            expires_at_unix_secs: row
                .get::<Option<i64>, _>("expires_at_unix_secs")
                .map(i64_to_u64)
                .transpose()?,
            created_at_unix_secs: i64_to_u64(row.get::<i64, _>("created_at_unix_secs"))?,
            last_used_at_unix_secs: row
                .get::<Option<i64>, _>("last_used_at_unix_secs")
                .map(i64_to_u64)
                .transpose()?,
            revoked_at_unix_secs: row
                .get::<Option<i64>, _>("revoked_at_unix_secs")
                .map(i64_to_u64)
                .transpose()?,
            usage_count: i64_to_u64(row.get::<i64, _>("usage_count"))?,
            state: AuthKeyState::parse(&state).ok_or_else(|| {
                AppError::Bootstrap(format!("unsupported auth key state in database: {state}"))
            })?,
        },
        secret_hash: row.get("secret_hash"),
    })
}

fn map_audit_event_row(row: sqlx::postgres::PgRow) -> AppResult<AuditEvent> {
    let kind = row.get::<String, _>("kind");
    let occurred_at_unix_secs = row.get::<i64, _>("occurred_at_unix_secs");

    Ok(AuditEvent {
        id: row.get("id"),
        actor: AuditActor {
            subject: row.get("actor_subject"),
            mechanism: row.get("actor_mechanism"),
        },
        kind: AuditEventKind::parse(&kind).ok_or_else(|| {
            AppError::Bootstrap(format!("unsupported audit event kind in database: {kind}"))
        })?,
        target: row.get("target"),
        occurred_at_unix_secs: i64_to_u64(occurred_at_unix_secs)?,
    })
}

fn map_database_write_error(error: sqlx::Error) -> AppError {
    match &error {
        sqlx::Error::Database(db_error) if db_error.is_unique_violation() => {
            AppError::Conflict("resource already exists with the same unique key".to_string())
        }
        _ => AppError::Database(error),
    }
}

async fn reset_nodes_sequence(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    max_node_id: u64,
    has_rows: bool,
) -> AppResult<()> {
    let sequence_value = if has_rows { max_node_id } else { 1 };

    sqlx::query("SELECT setval(pg_get_serial_sequence('nodes', 'id'), $1, $2)")
        .bind(u64_to_i64(sequence_value)?)
        .bind(has_rows)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

async fn reset_principals_sequence(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    max_principal_id: u64,
    has_rows: bool,
) -> AppResult<()> {
    let sequence_value = if has_rows { max_principal_id } else { 1 };

    sqlx::query("SELECT setval(pg_get_serial_sequence('principals', 'id'), $1, $2)")
        .bind(u64_to_i64(sequence_value)?)
        .bind(has_rows)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

async fn reset_routes_sequence(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    max_route_id: u64,
    has_rows: bool,
) -> AppResult<()> {
    let sequence_value = if has_rows { max_route_id } else { 1 };

    sqlx::query("SELECT setval(pg_get_serial_sequence('routes', 'id'), $1, $2)")
        .bind(u64_to_i64(sequence_value)?)
        .bind(has_rows)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

fn now_unix_secs() -> AppResult<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| AppError::Bootstrap(format!("system clock error: {err}")))?;
    Ok(duration.as_secs())
}

fn generate_auth_key_secret() -> String {
    format!("rsk_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn generate_node_session_secret() -> String {
    format!("rss_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn next_session_expiry_unix_secs(ttl_secs: u64) -> AppResult<u64> {
    now_unix_secs()?
        .checked_add(ttl_secs)
        .ok_or_else(|| AppError::Bootstrap("session expiry overflow".to_string()))
}

fn hash_secret(secret: &str) -> String {
    let digest = Sha256::hash(secret.as_bytes());
    let mut value = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn allocate_next_ipv4(cidr: &str, used: &std::collections::BTreeSet<String>) -> AppResult<String> {
    let (network, prefix_len) = parse_ipv4_cidr(cidr)?;
    let mask = ipv4_mask(prefix_len);
    let network = network & mask;
    let broadcast = network | !mask;

    for candidate in (network + 1)..broadcast {
        let address = std::net::Ipv4Addr::from(candidate).to_string();
        if !used.contains(&address) {
            return Ok(address);
        }
    }

    Err(AppError::Conflict(format!(
        "IPv4 address pool exhausted for {cidr}"
    )))
}

fn allocate_next_ipv6(cidr: &str, used: &std::collections::BTreeSet<String>) -> AppResult<String> {
    let (network, prefix_len) = parse_ipv6_cidr(cidr)?;
    let mask = ipv6_mask(prefix_len);
    let network = network & mask;
    let host_capacity = 128_u32.saturating_sub(u32::from(prefix_len));
    let last = if host_capacity == 128 {
        u128::MAX
    } else {
        network | ((1_u128 << host_capacity) - 1)
    };

    let mut candidate = network + 1;
    while candidate <= last {
        let address = std::net::Ipv6Addr::from(candidate).to_string();
        if !used.contains(&address) {
            return Ok(address);
        }
        candidate = candidate.saturating_add(1);
    }

    Err(AppError::Conflict(format!(
        "IPv6 address pool exhausted for {cidr}"
    )))
}

fn parse_ipv4(value: &str) -> AppResult<std::net::Ipv4Addr> {
    value
        .parse()
        .map_err(|err| AppError::InvalidRequest(format!("invalid IPv4 address {value}: {err}")))
}

fn parse_ipv6(value: &str) -> AppResult<std::net::Ipv6Addr> {
    value
        .parse()
        .map_err(|err| AppError::InvalidRequest(format!("invalid IPv6 address {value}: {err}")))
}

fn parse_ipv4_cidr(value: &str) -> AppResult<(u32, u8)> {
    let (address, prefix_len) = value
        .split_once('/')
        .ok_or_else(|| AppError::InvalidConfig(format!("invalid IPv4 CIDR notation: {value}")))?;
    let address = u32::from(parse_ipv4(address)?);
    let prefix_len: u8 = prefix_len.parse().map_err(|err| {
        AppError::InvalidConfig(format!("invalid IPv4 prefix length in {value}: {err}"))
    })?;
    if prefix_len > 30 {
        return Err(AppError::InvalidConfig(format!(
            "IPv4 CIDR {value} must allow at least two usable addresses"
        )));
    }
    Ok((address, prefix_len))
}

fn parse_ipv6_cidr(value: &str) -> AppResult<(u128, u8)> {
    let (address, prefix_len) = value
        .split_once('/')
        .ok_or_else(|| AppError::InvalidConfig(format!("invalid IPv6 CIDR notation: {value}")))?;
    let address = u128::from(parse_ipv6(address)?);
    let prefix_len: u8 = prefix_len.parse().map_err(|err| {
        AppError::InvalidConfig(format!("invalid IPv6 prefix length in {value}: {err}"))
    })?;
    if prefix_len > 127 {
        return Err(AppError::InvalidConfig(format!(
            "IPv6 CIDR {value} must allow at least one allocatable address"
        )));
    }
    Ok((address, prefix_len))
}

fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    }
}

fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    }
}

fn effective_node_status(mut node: Node, now_unix_secs: u64, online_window_secs: u64) -> Node {
    if matches!(node.status, NodeStatus::Disabled | NodeStatus::Pending) {
        return node;
    }

    node.status = match node.last_seen_unix_secs {
        Some(last_seen) if now_unix_secs.saturating_sub(last_seen) <= online_window_secs => {
            NodeStatus::Online
        }
        Some(_) => NodeStatus::Offline,
        None => NodeStatus::Pending,
    };

    node
}

fn effective_admin_node_status(
    status: NodeStatus,
    last_seen_unix_secs: Option<u64>,
    session_expires_at_unix_secs: Option<u64>,
    now_unix_secs: u64,
    online_window_secs: u64,
) -> NodeStatus {
    match status {
        NodeStatus::Disabled | NodeStatus::Pending | NodeStatus::Expired => status,
        NodeStatus::Online | NodeStatus::Offline => {
            if session_expires_at_unix_secs.is_some_and(|expiry| expiry <= now_unix_secs) {
                return NodeStatus::Expired;
            }

            match last_seen_unix_secs {
                Some(last_seen)
                    if now_unix_secs.saturating_sub(last_seen) <= online_window_secs =>
                {
                    NodeStatus::Online
                }
                Some(_) => NodeStatus::Offline,
                None => NodeStatus::Pending,
            }
        }
    }
}

fn restored_node_status(status: &NodeStatus) -> NodeStatus {
    match status {
        NodeStatus::Online => NodeStatus::Offline,
        other => other.clone(),
    }
}

fn i64_to_u64(value: i64) -> AppResult<u64> {
    value
        .try_into()
        .map_err(|_| AppError::Bootstrap(format!("database returned negative identifier: {value}")))
}

fn u64_to_i64(value: u64) -> AppResult<i64> {
    value.try_into().map_err(|_| {
        AppError::InvalidRequest(format!(
            "identifier {value} does not fit into PostgreSQL bigint"
        ))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::error::Error;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn node(id: u64, principal_id: Option<u64>, tags: &[&str]) -> Node {
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
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            tag_source: if tags.is_empty() {
                NodeTagSource::None
            } else {
                NodeTagSource::Request
            },
            last_seen_unix_secs: None,
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
        approval: RouteApproval,
        approved_by_policy: bool,
        is_exit_node: bool,
    ) -> Route {
        Route {
            id,
            node_id,
            prefix: prefix.to_string(),
            advertised: true,
            approval,
            approved_by_policy,
            is_exit_node,
        }
    }

    #[tokio::test]
    async fn control_event_bus_increments_generation() -> TestResult {
        let pool =
            PgPoolOptions::new().connect_lazy("postgres://rscale:rscale@127.0.0.1:5432/rscale")?;
        let (control_updates, _) = watch::channel(0_u64);
        let store = PostgresStore {
            pool,
            network: NetworkConfig::default(),
            control_updates,
            control_instance_id: "instance-a".to_string(),
        };
        let mut receiver = store.subscribe_control_events();

        assert_eq!(*receiver.borrow(), 0);
        store.notify_control_change().await;
        assert!(receiver.has_changed()?);
        assert_eq!(*receiver.borrow_and_update(), 1);

        store.notify_control_change().await;
        assert!(receiver.has_changed()?);
        assert_eq!(*receiver.borrow_and_update(), 2);

        Ok(())
    }

    #[test]
    fn remote_control_notification_ignores_same_instance() {
        let (control_updates, _) = watch::channel(0_u64);

        apply_remote_control_notification(&control_updates, "instance-a", "instance-a");
        assert_eq!(*control_updates.borrow(), 0);

        apply_remote_control_notification(&control_updates, "instance-a", "instance-b");
        assert_eq!(*control_updates.borrow(), 1);
    }

    #[test]
    fn effective_admin_node_status_uses_runtime_presence_and_session_expiry() {
        let now = 10_000;
        let online_window = 120;

        assert_eq!(
            effective_admin_node_status(NodeStatus::Disabled, Some(now), Some(now + 60), now, online_window),
            NodeStatus::Disabled
        );
        assert_eq!(
            effective_admin_node_status(NodeStatus::Pending, None, None, now, online_window),
            NodeStatus::Pending
        );
        assert_eq!(
            effective_admin_node_status(NodeStatus::Expired, Some(now), Some(now - 1), now, online_window),
            NodeStatus::Expired
        );
        assert_eq!(
            effective_admin_node_status(NodeStatus::Online, Some(now - 30), Some(now + 600), now, online_window),
            NodeStatus::Online
        );
        assert_eq!(
            effective_admin_node_status(NodeStatus::Online, Some(now - 300), Some(now + 600), now, online_window),
            NodeStatus::Offline
        );
        assert_eq!(
            effective_admin_node_status(NodeStatus::Offline, Some(now - 30), Some(now + 600), now, online_window),
            NodeStatus::Online
        );
        assert_eq!(
            effective_admin_node_status(NodeStatus::Online, Some(now - 30), Some(now - 1), now, online_window),
            NodeStatus::Expired
        );
        assert_eq!(
            effective_admin_node_status(NodeStatus::Online, None, Some(now + 600), now, online_window),
            NodeStatus::Pending
        );
    }

    #[test]
    fn route_policy_reconciliation_auto_approves_pending_routes() -> TestResult {
        let policy = AclPolicy {
            groups: vec![crate::domain::PolicySubject {
                name: "netadmin".to_string(),
                members: vec!["alice@".to_string()],
            }],
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: crate::domain::AutoApproverPolicy {
                routes: std::collections::BTreeMap::from([(
                    "10.0.0.0/8".to_string(),
                    vec!["group:netadmin".to_string()],
                )]),
                exit_node: Vec::new(),
            },
            ssh_rules: Vec::new(),
        };
        let routes = vec![route(
            10,
            1,
            "10.1.0.0/24",
            RouteApproval::Pending,
            false,
            false,
        )];
        let nodes = vec![node(1, Some(10), &[])];
        let principals = vec![principal(10, "alice@example.com")];

        let updates = plan_route_policy_reconciliation(&policy, &routes, &nodes, &principals)?;

        assert_eq!(
            updates,
            vec![RoutePolicyApprovalUpdate {
                route_id: 10,
                approval: RouteApproval::Approved,
                approved_by_policy: true,
            }]
        );

        Ok(())
    }

    #[test]
    fn route_policy_reconciliation_preserves_manual_approvals() -> TestResult {
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: crate::domain::AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };
        let routes = vec![route(
            11,
            1,
            "10.2.0.0/24",
            RouteApproval::Approved,
            false,
            false,
        )];
        let nodes = vec![node(1, Some(10), &[])];
        let principals = vec![principal(10, "alice@example.com")];

        let updates = plan_route_policy_reconciliation(&policy, &routes, &nodes, &principals)?;

        assert!(updates.is_empty());

        Ok(())
    }

    #[test]
    fn route_policy_reconciliation_reverts_stale_policy_approvals() -> TestResult {
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: crate::domain::AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };
        let routes = vec![route(
            12,
            2,
            "0.0.0.0/0",
            RouteApproval::Approved,
            true,
            true,
        )];
        let nodes = vec![node(2, None, &["tag:exit"])];
        let principals = Vec::new();

        let updates = plan_route_policy_reconciliation(&policy, &routes, &nodes, &principals)?;

        assert_eq!(
            updates,
            vec![RoutePolicyApprovalUpdate {
                route_id: 12,
                approval: RouteApproval::Pending,
                approved_by_policy: false,
            }]
        );

        Ok(())
    }
}
