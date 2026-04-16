use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::time::{Duration, Instant, sleep};
use uuid::Uuid;

use crate::config::{
    AppConfig, ControlClientVersionConfig, ControlDialCandidateConfig,
    ControlDisplayMessageActionConfig, ControlDisplayMessageConfig,
    ControlDisplayMessageSeverityConfig, ControlNodeAttrsConfig,
};
use crate::domain::{
    CompiledAclDestination, CompiledAclRule, CompiledCapGrant as DomainCapGrant,
    CompiledCapGrantRule as DomainCapGrantRule, CompiledGrantIpRule as DomainGrantIpRule,
    CompiledSshAction as DomainSshAction, CompiledSshPrincipal as DomainSshPrincipal,
    CompiledSshRule as DomainSshRule, DnsConfig, NodeStatus, NodeTagSource, PolicyPortRange,
    RouteApproval,
};
use crate::error::{AppError, AppResult};
use crate::infra::auth::oidc::OidcRuntime;
use crate::infra::db::{ControlNodeRecord, PostgresStore};
use crate::infra::derp::DerpMapRuntime;

use super::types::{
    ControlCapGrant, ControlClientVersion, ControlDerpMap, ControlDialPlan, ControlDisplayMessage,
    ControlDisplayMessageAction, ControlDisplayMessageSeverity, ControlDnsConfig,
    ControlDnsResolver, ControlFilterRule, ControlIpCandidate, ControlLogin, ControlNetPortRange,
    ControlNode, ControlPeerChange, ControlPortRange, ControlSshAction, ControlSshPolicy,
    ControlSshPrincipal, ControlSshRule, ControlUser, ControlUserProfile, MapRequest, MapResponse,
    RegisterRequest, RegisterResponse,
};
use super::{legacy_derp, preferred_derp};

const LOCAL_IDENTITY_OFFSET: u64 = 1_000_000_000_000;
const CAP_PEER_SEEN_CHANGE: u32 = 10;
const CAP_ONLINE_CHANGE: u32 = 16;
const CAP_HEALTH: u32 = 24;
const CAP_SSH_POLICY: u32 = 27;
const CAP_POP_BROWSER_URL: u32 = 29;
const CAP_PEERS_CHANGED_PATCH: u32 = 33;
const CAP_SSH_USERNAMES: u32 = 43;
const CAP_PEER_PATCH_KEY_FIELDS: u32 = 36;
const CAP_CONTROL_DIAL_PLAN: u32 = 44;
const CAP_PEER_PATCH_CAP: u32 = 54;
const CAP_NODE_CAP_MAP: u32 = 74;
const CAP_CLIENT_VERSION: u32 = 73;
const CAP_CLIENT_VERSION_URGENT_SECURITY_UPDATE: u32 = 79;
const CAP_DEPRECATED_DEFAULT_AUTO_UPDATE: u32 = 83;
const CAP_NODE_ATTR_USER_DIAL_USE_ROUTES: u32 = 92;
const CAP_NODE_ATTR_DISABLE_CAPTIVE_PORTAL_DETECTION: u32 = 103;
const CAP_NODE_ATTR_MAX_KEY_DURATION: u32 = 114;
const CAP_NODE_ATTR_MAGICDNS_PEER_AAAA: u32 = 116;
const CAP_DISPLAY_MESSAGES: u32 = 117;
const CAP_NODE_ATTR_DEFAULT_AUTO_UPDATE: u32 = 131;
const CAP_NODE_ATTR_DISABLE_HOSTS_FILE_UPDATES: u32 = 132;
const CAP_NODE_ATTR_FORCE_REGISTER_MAGICDNS_IPV4_ONLY: u32 = 133;
const CAP_NODE_ATTR_CACHE_NETWORK_MAPS: u32 = 135;
const DEFAULT_SSH_CHECK_PERIOD_SECS: u64 = 12 * 60 * 60;
type ControlDisplayMessagePatch = BTreeMap<String, Option<ControlDisplayMessage>>;
type ControlHealthState = (Option<Vec<String>>, Option<ControlDisplayMessagePatch>);
type ControlNodeCapMap = BTreeMap<String, Vec<serde_json::Value>>;

#[derive(Debug, Clone)]
struct IdentityView {
    user: ControlUser,
    login: ControlLogin,
    profile: ControlUserProfile,
}

#[derive(Debug, Clone)]
struct SshActionBinding {
    ssh_user: String,
    local_user: String,
}

#[derive(Clone)]
pub struct ControlService {
    config: AppConfig,
    store: PostgresStore,
    derp: DerpMapRuntime,
    oidc: Option<OidcRuntime>,
}

impl ControlService {
    pub fn new(
        config: AppConfig,
        store: PostgresStore,
        derp: DerpMapRuntime,
        oidc: Option<OidcRuntime>,
    ) -> Self {
        Self {
            config,
            store,
            derp,
            oidc,
        }
    }

    pub fn subscribe_map_updates(&self) -> tokio::sync::watch::Receiver<u64> {
        self.store.subscribe_control_events()
    }

    pub async fn register(
        &self,
        machine_key: &str,
        request: RegisterRequest,
    ) -> AppResult<RegisterResponse> {
        if !request.followup.trim().is_empty() {
            return self.wait_for_oidc_followup(machine_key, request).await;
        }

        let has_auth_key = request
            .auth
            .as_ref()
            .is_some_and(|auth| !auth.auth_key.trim().is_empty());
        let existing_node = self
            .store
            .get_control_node_by_machine_key(machine_key)
            .await?;
        let record = if has_auth_key
            || existing_node.as_ref().is_some_and(|existing_node| {
                !register_request_requires_interactive_auth(
                    &request,
                    Some(existing_node.node.tag_source),
                )
            }) {
            self.store
                .register_control_node(machine_key, &request)
                .await?
        } else if let Some(oidc) = &self.oidc {
            let pending = self
                .store
                .begin_oidc_auth_request(machine_key, &request, oidc.auth_flow_ttl_secs())
                .await?;
            return Ok(RegisterResponse {
                auth_url: oidc.registration_url(&pending.auth_id),
                machine_authorized: false,
                ..RegisterResponse::default()
            });
        } else {
            return Err(crate::error::AppError::Unauthorized(
                "interactive registration is not configured; Auth.AuthKey is required".to_string(),
            ));
        };

        register_response_for_record(&record)
    }

    pub async fn prepare_map_node(
        &self,
        machine_key: &str,
        request: &MapRequest,
    ) -> AppResult<ControlNodeRecord> {
        self.store.touch_control_node(machine_key, request).await
    }

    pub async fn build_one_shot_map(
        &self,
        node_id: u64,
        seq: i64,
        session_handle: Option<&str>,
    ) -> AppResult<MapResponse> {
        let mut response = self.build_map_state(node_id).await?;
        response.seq = seq;
        response.control_time = Some(now_rfc3339()?);
        if let Some(session_handle) = session_handle {
            response.map_session_handle = session_handle.to_string();
            self.store
                .store_control_session(node_id, session_handle, seq)
                .await?;
        }

        Ok(response)
    }

    pub async fn build_stream_state(
        &self,
        node_id: u64,
        seq: i64,
    ) -> AppResult<(String, MapResponse, Vec<u8>)> {
        let session_handle = Uuid::new_v4().to_string();
        let mut response = self.build_map_state(node_id).await?;
        response.seq = seq;
        response.map_session_handle = session_handle.clone();
        response.control_time = Some(now_rfc3339()?);
        self.store
            .store_control_session(node_id, &session_handle, seq)
            .await?;

        let signature = response_signature(&response)?;
        Ok((session_handle, response, signature))
    }

    pub async fn refresh_stream_state(
        &self,
        node_id: u64,
        seq: i64,
    ) -> AppResult<(MapResponse, Vec<u8>)> {
        let mut response = self.build_map_state(node_id).await?;
        response.seq = seq;
        response.control_time = Some(now_rfc3339()?);
        let signature = response_signature(&response)?;
        Ok((response, signature))
    }

    pub async fn resolve_ssh_action(
        &self,
        machine_key: &str,
        src_node_id: u64,
        dst_node_id: u64,
        auth_id: Option<&str>,
        ssh_user: Option<&str>,
        local_user: Option<&str>,
    ) -> AppResult<ControlSshAction> {
        let dst_node = self.store.get_control_node(dst_node_id).await?;
        if dst_node.machine_key != machine_key {
            return Err(crate::error::AppError::Unauthorized(
                "Noise session machine key does not match SSH destination node".to_string(),
            ));
        }

        let src_node = self.store.get_control_node(src_node_id).await?;
        let nodes = self
            .store
            .list_control_nodes()
            .await?
            .into_iter()
            .map(|record| record.node)
            .collect::<Vec<_>>();
        let routes = self.store.list_routes().await?;
        let policy = self.store.load_policy().await?;
        let ssh_binding = ssh_action_binding(dst_node.map_request_version, ssh_user, local_user)?;
        let (check_action, ssh_user, local_user) = if let Some(binding) = ssh_binding.as_ref() {
            let (action, local_user) = policy
                .ssh_check_action_for_connection(
                    &src_node.node,
                    &dst_node.node,
                    &binding.ssh_user,
                    Some(&binding.local_user),
                    &nodes,
                    &routes,
                )?
                .ok_or_else(|| {
                    crate::error::AppError::Unauthorized(
                        "SSH check-mode is not enabled for this source/destination user mapping"
                            .to_string(),
                    )
                })?;
            (action, binding.ssh_user.clone(), local_user)
        } else {
            let action = policy
                .ssh_check_action_for_pair(&src_node.node, &dst_node.node, &nodes, &routes)?
                .ok_or_else(|| {
                    crate::error::AppError::Unauthorized(
                        "SSH check-mode is not enabled for this source/destination pair"
                            .to_string(),
                    )
                })?;
            (action, String::new(), String::new())
        };
        let check_period_secs = check_action
            .check_period_secs
            .unwrap_or(DEFAULT_SSH_CHECK_PERIOD_SECS);

        if let Some(auth_id) = auth_id {
            return self
                .wait_for_ssh_auth_resolution(
                    auth_id,
                    src_node_id,
                    dst_node_id,
                    &ssh_user,
                    &local_user,
                    &check_action,
                )
                .await;
        }

        if let Some(last_approved_at) = self
            .store
            .last_ssh_check_approval(src_node_id, dst_node_id, &ssh_user, &local_user)
            .await?
            && now_unix_secs()?.saturating_sub(last_approved_at) < check_period_secs
        {
            return Ok(approved_ssh_action_from_check(&check_action));
        }

        let oidc = self.oidc.as_ref().ok_or_else(|| {
            crate::error::AppError::InvalidConfig(
                "SSH check-mode requires OIDC to be enabled".to_string(),
            )
        })?;
        let pending = self
            .store
            .create_ssh_auth_request(
                src_node_id,
                dst_node_id,
                &ssh_user,
                &local_user,
                oidc.auth_flow_ttl_secs(),
            )
            .await?;
        let approval_url = self.ssh_browser_auth_url(&pending.auth_id)?;
        let mut action = check_ssh_action_prompt(&check_action, &self.config, &pending.auth_id);
        action.message = format!(
            "# rscale SSH requires an additional check.\n# To authenticate, visit: {approval_url}\n# Authentication checked with rscale SSH.\n"
        );
        Ok(action)
    }

    fn ssh_browser_auth_url(&self, auth_id: &str) -> AppResult<String> {
        let base_url = self
            .config
            .server
            .public_base_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                crate::error::AppError::InvalidConfig(
                    "server.public_base_url is required for SSH check-mode".to_string(),
                )
            })?;
        Ok(format!(
            "{}/ssh/check/{auth_id}",
            base_url.trim_end_matches('/')
        ))
    }

    async fn wait_for_ssh_auth_resolution(
        &self,
        auth_id: &str,
        src_node_id: u64,
        dst_node_id: u64,
        ssh_user: &str,
        local_user: &str,
        check_action: &DomainSshAction,
    ) -> AppResult<ControlSshAction> {
        loop {
            let pending = self.store.get_ssh_auth_request(auth_id).await?;
            if pending.src_node_id != src_node_id || pending.dst_node_id != dst_node_id {
                return Err(crate::error::AppError::Unauthorized(
                    "SSH auth session does not match the requested source/destination pair"
                        .to_string(),
                ));
            }
            if pending.ssh_user != ssh_user || pending.local_user != local_user {
                return Err(crate::error::AppError::Unauthorized(
                    "SSH auth session does not match the requested ssh_user/local_user".to_string(),
                ));
            }

            match pending.status {
                crate::infra::db::SshAuthRequestStatus::Pending => {
                    if now_unix_secs()? >= pending.expires_at_unix_secs {
                        return Err(crate::error::AppError::Unauthorized(
                            "SSH auth request expired before approval completed".to_string(),
                        ));
                    }
                    sleep(Duration::from_secs(1)).await;
                }
                crate::infra::db::SshAuthRequestStatus::Approved => {
                    self.store
                        .record_ssh_check_approval(src_node_id, dst_node_id, ssh_user, local_user)
                        .await?;
                    return Ok(approved_ssh_action_from_check(check_action));
                }
                crate::infra::db::SshAuthRequestStatus::Rejected => {
                    let mut action = rejected_ssh_action_from_check(check_action);
                    action.message = pending
                        .message
                        .unwrap_or_else(|| "SSH authentication was rejected".to_string());
                    return Ok(action);
                }
            }
        }
    }

    async fn build_map_state(&self, node_id: u64) -> AppResult<MapResponse> {
        let all_nodes = self.store.list_control_nodes().await?;
        let routes = self.store.list_routes().await?;
        let policy = self.store.load_policy().await?;
        let dns = self.store.load_dns_config().await?;
        let derp_map = self.derp.effective_map();
        let self_node = all_nodes
            .iter()
            .find(|node| node.node.id == node_id)
            .cloned()
            .ok_or_else(|| {
                AppError::NotFound(format!("control node {node_id} is not registered"))
            })?;
        let domain_nodes = all_nodes
            .iter()
            .map(|node| node.node.clone())
            .collect::<Vec<_>>();
        let online_node_ids = all_nodes
            .iter()
            .filter(|node| is_online(&self.config, node))
            .map(|node| node.node.id)
            .collect::<std::collections::BTreeSet<_>>();

        let approved_routes = routes
            .into_iter()
            .filter(|route| {
                route.approval == RouteApproval::Approved
                    && route.advertised
                    && online_node_ids.contains(&route.node_id)
            })
            .collect::<Vec<_>>();
        let evaluated_policy =
            policy.evaluate_for_node(&self_node.node, &domain_nodes, &approved_routes)?;
        let route_map = approved_route_map(
            &approved_routes
                .iter()
                .filter(|route| {
                    route.node_id == self_node.node.id
                        || evaluated_policy.visible_route_ids.contains(&route.id)
                })
                .cloned()
                .collect::<Vec<_>>(),
        );
        let packet_filter = to_control_filter_rules(
            &evaluated_policy.packet_rules,
            &evaluated_policy.grant_ip_rules,
            &evaluated_policy.cap_grant_rules,
        );
        let cap_version = self_node.map_request_version;
        let (health, display_messages) =
            control_health_state(cap_version, &self.config, self.derp.status());
        let ssh_policy = control_ssh_policy(
            cap_version,
            &policy,
            &self_node.node,
            &domain_nodes,
            &approved_routes,
            &self.config,
            self.oidc.is_some(),
        )?;
        let control_dial_plan = control_dial_plan(cap_version, &self.config);
        let pop_browser_url = control_pop_browser_url(cap_version, &self.config);
        let client_version = control_client_version(
            cap_version,
            self_node.hostinfo.as_ref(),
            &self.config.control.client_version,
        );
        let deprecated_default_auto_update =
            deprecated_default_auto_update(cap_version, &self.config.control.node_attrs);
        let collect_services = self.config.control.collect_services;
        let (self_capabilities, self_cap_map) =
            control_self_node_capabilities(cap_version, &self.config.control.node_attrs);

        let visible_peer_records = all_nodes
            .iter()
            .filter(|node| {
                node.node.id != node_id
                    && node.node.status != NodeStatus::Disabled
                    && evaluated_policy.visible_peer_ids.contains(&node.node.id)
            })
            .cloned()
            .collect::<Vec<_>>();
        let peers = visible_peer_records
            .iter()
            .map(|node| {
                self.to_tail_node(
                    node,
                    &route_map,
                    &dns,
                    &derp_map,
                    Vec::new(),
                    BTreeMap::new(),
                )
            })
            .collect::<AppResult<Vec<_>>>()?;
        let self_tail_node = self.to_tail_node(
            &self_node,
            &route_map,
            &dns,
            &derp_map,
            self_capabilities,
            self_cap_map,
        )?;
        let mut user_profiles = BTreeMap::<u64, ControlUserProfile>::new();
        for record in std::iter::once(&self_node).chain(visible_peer_records.iter()) {
            let identity = identity_view(record)?;
            user_profiles
                .entry(identity.profile.id)
                .or_insert(identity.profile);
        }

        Ok(MapResponse {
            pop_browser_url,
            node: Some(self_tail_node),
            derp_map: Some(derp_map),
            peers,
            dns_config: Some(to_control_dns_config(&dns)),
            domain: default_domain(&self.config, &dns),
            collect_services,
            packet_filter: Some(packet_filter.clone()),
            packet_filters: Some(BTreeMap::from([("base".to_string(), packet_filter)])),
            user_profiles: user_profiles.into_values().collect(),
            health,
            display_messages,
            ssh_policy,
            control_dial_plan,
            client_version,
            deprecated_default_auto_update,
            ..MapResponse::default()
        })
    }

    fn to_tail_node(
        &self,
        node: &ControlNodeRecord,
        route_map: &BTreeMap<u64, Vec<String>>,
        dns: &DnsConfig,
        derp_map: &ControlDerpMap,
        capabilities: Vec<String>,
        cap_map: ControlNodeCapMap,
    ) -> AppResult<ControlNode> {
        let mut addresses = Vec::new();
        if let Some(ipv4) = &node.node.ipv4 {
            addresses.push(format!("{ipv4}/32"));
        }
        if let Some(ipv6) = &node.node.ipv6 {
            addresses.push(format!("{ipv6}/128"));
        }

        let primary_routes = route_map.get(&node.node.id).cloned().unwrap_or_default();
        let mut allowed_ips = addresses.clone();
        allowed_ips.extend(primary_routes.clone());
        let home_derp = preferred_derp(node.hostinfo.as_ref(), derp_map);
        let identity = identity_view(node)?;

        Ok(ControlNode {
            id: node.node.id,
            stable_id: node.node.stable_id.clone(),
            name: fqdn(&node.node.hostname, dns),
            user: identity.user.id,
            key: node.node_key.clone(),
            key_expiry: node
                .key_expiry_unix_secs
                .map(format_unix_secs)
                .transpose()?
                .unwrap_or_default(),
            machine: node.machine_key.clone(),
            disco_key: node.disco_key.clone(),
            addresses,
            allowed_ips,
            endpoints: node.endpoints.clone(),
            legacy_derp_string: legacy_derp(home_derp),
            home_derp,
            hostinfo: node.hostinfo.clone(),
            created: format_unix_secs(node.created_at_unix_secs)?,
            cap: node.map_request_version,
            tags: node.node.tags.clone(),
            primary_routes,
            last_seen: node
                .node
                .last_seen_unix_secs
                .map(format_unix_secs)
                .transpose()?
                .unwrap_or_default(),
            online: Some(is_online(&self.config, node)),
            machine_authorized: node.node.status != NodeStatus::Disabled,
            capabilities,
            cap_map,
            expired: node.node.status == NodeStatus::Expired,
        })
    }

    async fn wait_for_oidc_followup(
        &self,
        machine_key: &str,
        request: RegisterRequest,
    ) -> AppResult<RegisterResponse> {
        let Some(oidc) = &self.oidc else {
            return Err(crate::error::AppError::Unauthorized(
                "interactive registration is not configured".to_string(),
            ));
        };

        let auth_id = extract_followup_auth_id(&request.followup)?;
        let deadline = Instant::now() + Duration::from_secs(55);

        loop {
            match self.store.get_oidc_auth_request(&auth_id).await {
                Ok(pending) => {
                    if pending.completed_at_unix_secs.is_some() {
                        let record = self
                            .store
                            .register_control_node_from_oidc_auth(machine_key, &auth_id, &request)
                            .await?;
                        return register_response_for_record(&record);
                    }

                    if Instant::now() >= deadline {
                        return Ok(RegisterResponse {
                            auth_url: oidc.registration_url(&auth_id),
                            machine_authorized: false,
                            ..RegisterResponse::default()
                        });
                    }
                }
                Err(crate::error::AppError::NotFound(_)) => {
                    let pending = self
                        .store
                        .begin_oidc_auth_request(machine_key, &request, oidc.auth_flow_ttl_secs())
                        .await?;
                    return Ok(RegisterResponse {
                        auth_url: oidc.registration_url(&pending.auth_id),
                        machine_authorized: false,
                        ..RegisterResponse::default()
                    });
                }
                Err(err) => return Err(err),
            }

            sleep(Duration::from_millis(500)).await;
        }
    }
}

pub fn response_signature(response: &MapResponse) -> AppResult<Vec<u8>> {
    #[derive(Serialize)]
    struct Comparable<'a> {
        pop_browser_url: &'a String,
        node: &'a Option<ControlNode>,
        derp_map: &'a Option<ControlDerpMap>,
        peers: &'a Vec<ControlNode>,
        dns_config: &'a Option<ControlDnsConfig>,
        domain: &'a String,
        collect_services: &'a Option<bool>,
        packet_filter: &'a Option<Vec<ControlFilterRule>>,
        packet_filters: &'a Option<BTreeMap<String, Vec<ControlFilterRule>>>,
        user_profiles: &'a Vec<ControlUserProfile>,
        health: &'a Option<Vec<String>>,
        display_messages: &'a Option<BTreeMap<String, Option<ControlDisplayMessage>>>,
        ssh_policy: &'a Option<ControlSshPolicy>,
        control_dial_plan: &'a Option<ControlDialPlan>,
        client_version: &'a Option<ControlClientVersion>,
        deprecated_default_auto_update: &'a Option<bool>,
    }

    Ok(serde_json::to_vec(&Comparable {
        pop_browser_url: &response.pop_browser_url,
        node: &response.node,
        derp_map: &response.derp_map,
        peers: &response.peers,
        dns_config: &response.dns_config,
        domain: &response.domain,
        collect_services: &response.collect_services,
        packet_filter: &response.packet_filter,
        packet_filters: &response.packet_filters,
        user_profiles: &response.user_profiles,
        health: &response.health,
        display_messages: &response.display_messages,
        ssh_policy: &response.ssh_policy,
        control_dial_plan: &response.control_dial_plan,
        client_version: &response.client_version,
        deprecated_default_auto_update: &response.deprecated_default_auto_update,
    })?)
}

pub fn incremental_map_response(
    previous: &MapResponse,
    current: &MapResponse,
) -> Option<MapResponse> {
    let cap_version = current.node.as_ref().map_or(0, |node| node.cap);
    let mut response = MapResponse {
        seq: current.seq,
        control_time: current.control_time.clone(),
        ..MapResponse::default()
    };
    let mut changed = false;

    if previous.pop_browser_url != current.pop_browser_url {
        response.pop_browser_url = current.pop_browser_url.clone();
        changed = true;
    }
    if previous.node != current.node {
        response.node = current.node.clone();
        changed = true;
    }
    if previous.derp_map != current.derp_map {
        response.derp_map = current.derp_map.clone();
        changed = true;
    }
    if previous.dns_config != current.dns_config {
        response.dns_config = current.dns_config.clone();
        changed = true;
    }
    if previous.domain != current.domain {
        response.domain = current.domain.clone();
        changed = true;
    }
    if previous.collect_services != current.collect_services {
        response.collect_services = current.collect_services;
        changed = true;
    }
    if previous.packet_filter != current.packet_filter {
        response.packet_filter = current.packet_filter.clone();
        changed = true;
    }
    if previous.packet_filters != current.packet_filters {
        response.packet_filters = current.packet_filters.clone();
        changed = true;
    }
    if previous.health != current.health {
        response.health = current.health.clone();
        changed = true;
    }
    if let Some(display_messages) = incremental_display_messages(
        previous.display_messages.as_ref(),
        current.display_messages.as_ref(),
    ) {
        response.display_messages = Some(display_messages);
        changed = true;
    }
    if previous.ssh_policy != current.ssh_policy {
        response.ssh_policy = current
            .ssh_policy
            .clone()
            .or(Some(ControlSshPolicy::default()));
        changed = true;
    }
    if previous.control_dial_plan != current.control_dial_plan {
        response.control_dial_plan = current.control_dial_plan.clone();
        changed = true;
    }
    if previous.client_version != current.client_version {
        response.client_version = current.client_version.clone();
        changed = true;
    }
    if previous.deprecated_default_auto_update != current.deprecated_default_auto_update {
        response.deprecated_default_auto_update = current.deprecated_default_auto_update;
        changed = true;
    }

    let previous_peers = previous
        .peers
        .iter()
        .map(|peer| (peer.id, peer))
        .collect::<BTreeMap<_, _>>();
    let current_peers = current
        .peers
        .iter()
        .map(|peer| (peer.id, peer))
        .collect::<BTreeMap<_, _>>();

    for (id, peer) in &current_peers {
        let Some(previous_peer) = previous_peers.get(id) else {
            response.peers_changed.push((**peer).clone());
            continue;
        };

        match peer_delta(previous_peer, peer, cap_version) {
            PeerDelta::Unchanged => {}
            PeerDelta::Full => response.peers_changed.push((**peer).clone()),
            PeerDelta::Patch(change) => response.peers_changed_patch.push(change),
            PeerDelta::Online(is_online) => {
                response.online_change.insert(*id, is_online);
            }
            PeerDelta::LastSeen(is_seen) => {
                response.peer_seen_change.insert(*id, is_seen);
            }
            PeerDelta::OnlineAndLastSeen { online, seen } => {
                response.online_change.insert(*id, online);
                response.peer_seen_change.insert(*id, seen);
            }
        }
    }
    response.peers_removed = previous_peers
        .keys()
        .filter(|id| !current_peers.contains_key(id))
        .copied()
        .collect();
    if !response.peers_changed.is_empty()
        || !response.peers_removed.is_empty()
        || !response.peers_changed_patch.is_empty()
        || !response.peer_seen_change.is_empty()
        || !response.online_change.is_empty()
    {
        changed = true;
    }

    let previous_profiles = previous
        .user_profiles
        .iter()
        .map(|profile| (profile.id, profile))
        .collect::<BTreeMap<_, _>>();
    response.user_profiles = current
        .user_profiles
        .iter()
        .filter_map(|profile| match previous_profiles.get(&profile.id) {
            Some(previous_profile) if *previous_profile == profile => None,
            _ => Some(profile.clone()),
        })
        .collect();
    if !response.user_profiles.is_empty() {
        changed = true;
    }

    changed.then_some(response)
}

enum PeerDelta {
    Unchanged,
    Full,
    Patch(ControlPeerChange),
    Online(bool),
    LastSeen(bool),
    OnlineAndLastSeen { online: bool, seen: bool },
}

fn peer_delta(previous: &ControlNode, current: &ControlNode, cap_version: u32) -> PeerDelta {
    if previous == current {
        return PeerDelta::Unchanged;
    }

    if previous.id != current.id
        || previous.stable_id != current.stable_id
        || previous.name != current.name
        || previous.user != current.user
        || previous.machine != current.machine
        || previous.addresses != current.addresses
        || previous.allowed_ips != current.allowed_ips
        || previous.hostinfo != current.hostinfo
        || previous.created != current.created
        || previous.tags != current.tags
        || previous.primary_routes != current.primary_routes
        || previous.machine_authorized != current.machine_authorized
        || previous.capabilities != current.capabilities
        || previous.cap_map != current.cap_map
        || previous.expired != current.expired
    {
        return PeerDelta::Full;
    }

    let mut patch = ControlPeerChange {
        node_id: current.id,
        ..ControlPeerChange::default()
    };
    let mut has_patch = false;

    if previous.home_derp != current.home_derp {
        if cap_version < CAP_PEERS_CHANGED_PATCH {
            return PeerDelta::Full;
        }
        patch.derp_region = current.home_derp;
        has_patch = true;
    }

    if previous.endpoints != current.endpoints {
        if cap_version < CAP_PEERS_CHANGED_PATCH {
            return PeerDelta::Full;
        }
        patch.endpoints = current.endpoints.clone();
        has_patch = true;
    }

    if previous.key != current.key {
        if cap_version < CAP_PEER_PATCH_KEY_FIELDS {
            return PeerDelta::Full;
        }
        patch.key = current.key.clone();
        has_patch = true;
    }

    if previous.disco_key != current.disco_key {
        if cap_version < CAP_PEER_PATCH_KEY_FIELDS {
            return PeerDelta::Full;
        }
        patch.disco_key = current.disco_key.clone();
        has_patch = true;
    }

    if previous.key_expiry != current.key_expiry {
        if cap_version < CAP_PEER_PATCH_KEY_FIELDS {
            return PeerDelta::Full;
        }
        patch.key_expiry = current.key_expiry.clone();
        has_patch = true;
    }

    if previous.cap != current.cap {
        if cap_version < CAP_PEER_PATCH_CAP {
            return PeerDelta::Full;
        }
        patch.cap = current.cap;
        has_patch = true;
    }

    let online_changed = previous.online != current.online;
    let last_seen_changed = previous.last_seen != current.last_seen;

    if online_changed {
        if cap_version >= CAP_PEER_PATCH_KEY_FIELDS {
            patch.online = current.online;
            has_patch = true;
        } else if cap_version < CAP_ONLINE_CHANGE {
            return PeerDelta::Full;
        }
    }

    if last_seen_changed {
        if cap_version >= CAP_PEER_PATCH_KEY_FIELDS {
            patch.last_seen = current.last_seen.clone();
            has_patch = true;
        } else if cap_version < CAP_PEER_SEEN_CHANGE || current.last_seen.is_empty() {
            return PeerDelta::Full;
        }
    }

    if previous.legacy_derp_string != current.legacy_derp_string
        && previous.home_derp == current.home_derp
    {
        return PeerDelta::Full;
    }

    if has_patch {
        return PeerDelta::Patch(patch);
    }

    match (online_changed, last_seen_changed, current.online) {
        (true, true, Some(online)) => PeerDelta::OnlineAndLastSeen { online, seen: true },
        (true, false, Some(online)) => PeerDelta::Online(online),
        (false, true, _) => PeerDelta::LastSeen(true),
        (true, _, None) => PeerDelta::Full,
        _ => PeerDelta::Unchanged,
    }
}

fn incremental_display_messages(
    previous: Option<&ControlDisplayMessagePatch>,
    current: Option<&ControlDisplayMessagePatch>,
) -> Option<ControlDisplayMessagePatch> {
    if previous == current {
        return None;
    }

    let empty = BTreeMap::new();
    let previous = previous.unwrap_or(&empty);
    let current = current.unwrap_or(&empty);

    if current.is_empty() {
        return (!previous.is_empty()).then(|| BTreeMap::from([("*".to_string(), None)]));
    }

    let mut patch = BTreeMap::new();
    for (id, message) in current {
        if previous.get(id) != Some(message) {
            patch.insert(id.clone(), message.clone());
        }
    }
    for id in previous.keys() {
        if !current.contains_key(id) {
            patch.insert(id.clone(), None);
        }
    }

    (!patch.is_empty()).then_some(patch)
}

fn control_health_state(
    cap_version: u32,
    config: &AppConfig,
    derp_status: crate::infra::derp::DerpRuntimeStatus,
) -> ControlHealthState {
    let display_messages = control_display_messages(config, derp_status);

    if cap_version >= CAP_DISPLAY_MESSAGES {
        return (
            None,
            (!display_messages.is_empty()).then_some(display_messages),
        );
    }

    if cap_version < CAP_HEALTH {
        return (None, None);
    }

    let health = display_messages
        .values()
        .filter_map(|message| message.as_ref())
        .map(display_message_to_health_line)
        .collect::<Vec<_>>();
    (Some(health), None)
}

fn control_display_messages(
    config: &AppConfig,
    derp_status: crate::infra::derp::DerpRuntimeStatus,
) -> ControlDisplayMessagePatch {
    let mut messages = config
        .control
        .display_messages
        .iter()
        .map(|(id, message)| {
            (
                id.clone(),
                Some(control_display_message_from_config(message)),
            )
        })
        .collect::<BTreeMap<_, _>>();

    if let Some(error) = derp_status.last_refresh_error {
        messages.insert(
            "derp-refresh".to_string(),
            Some(ControlDisplayMessage {
                title: "DERP configuration refresh is failing".to_string(),
                text: format!(
                    "rscale could not refresh the DERP map and is keeping the last successful snapshot: {error}"
                ),
                severity: ControlDisplayMessageSeverity::Medium,
                impacts_connectivity: true,
                primary_action: None,
            }),
        );
    }

    messages
}

fn control_display_message_from_config(
    config: &ControlDisplayMessageConfig,
) -> ControlDisplayMessage {
    ControlDisplayMessage {
        title: config.title.clone(),
        text: config.text.clone(),
        severity: control_display_message_severity(&config.severity),
        impacts_connectivity: config.impacts_connectivity,
        primary_action: config
            .primary_action
            .as_ref()
            .map(control_display_message_action_from_config),
    }
}

fn control_display_message_action_from_config(
    config: &ControlDisplayMessageActionConfig,
) -> ControlDisplayMessageAction {
    ControlDisplayMessageAction {
        url: config.url.clone(),
        label: config.label.clone(),
    }
}

fn control_display_message_severity(
    severity: &ControlDisplayMessageSeverityConfig,
) -> ControlDisplayMessageSeverity {
    match severity {
        ControlDisplayMessageSeverityConfig::High => ControlDisplayMessageSeverity::High,
        ControlDisplayMessageSeverityConfig::Medium => ControlDisplayMessageSeverity::Medium,
        ControlDisplayMessageSeverityConfig::Low => ControlDisplayMessageSeverity::Low,
    }
}

fn display_message_to_health_line(message: &ControlDisplayMessage) -> String {
    format!("{}: {}", message.title, message.text)
}

fn control_dial_plan(cap_version: u32, config: &AppConfig) -> Option<ControlDialPlan> {
    if cap_version < CAP_CONTROL_DIAL_PLAN {
        return None;
    }

    let mut candidates = config
        .control
        .dial_plan
        .candidates
        .iter()
        .map(control_ip_candidate_from_config)
        .collect::<Vec<_>>();

    if candidates.is_empty()
        && let Some(public_base_url) = config.server.public_base_url.as_deref()
        && let Some(ip) = public_base_url_ip(public_base_url)
    {
        candidates.push(ControlIpCandidate {
            ip,
            ..ControlIpCandidate::default()
        });
    }

    Some(ControlDialPlan { candidates })
}

fn control_ssh_policy(
    cap_version: u32,
    policy: &crate::domain::AclPolicy,
    subject: &crate::domain::Node,
    nodes: &[crate::domain::Node],
    routes: &[crate::domain::Route],
    config: &AppConfig,
    oidc_enabled: bool,
) -> AppResult<Option<ControlSshPolicy>> {
    if cap_version < CAP_SSH_POLICY {
        return Ok(None);
    }

    if policy
        .ssh_rules
        .iter()
        .any(|rule| matches!(rule.action, crate::domain::SshPolicyAction::Check))
    {
        if !oidc_enabled {
            return Err(crate::error::AppError::InvalidConfig(
                "SSH check-mode rules require OIDC to be enabled".to_string(),
            ));
        }

        if config
            .server
            .public_base_url
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(crate::error::AppError::InvalidConfig(
                "SSH check-mode rules require server.public_base_url".to_string(),
            ));
        }
    }

    let compiled = policy.evaluate_ssh_for_node(subject, nodes, routes)?;
    Ok(Some(ControlSshPolicy {
        rules: compiled
            .rules
            .into_iter()
            .map(|rule| to_control_ssh_rule(rule, config))
            .collect(),
    }))
}

fn control_pop_browser_url(cap_version: u32, config: &AppConfig) -> String {
    if cap_version < CAP_POP_BROWSER_URL {
        return String::new();
    }

    config.control.pop_browser_url.clone().unwrap_or_default()
}

fn control_client_version(
    cap_version: u32,
    hostinfo: Option<&serde_json::Value>,
    config: &ControlClientVersionConfig,
) -> Option<ControlClientVersion> {
    if cap_version < CAP_CLIENT_VERSION {
        return None;
    }

    let latest_version = config.latest_version.as_deref()?;
    let current_version = hostinfo.and_then(hostinfo_ipn_version)?;
    let ordering = compare_release_versions(current_version, latest_version)?;

    if ordering != Ordering::Less {
        return Some(ControlClientVersion {
            running_latest: true,
            ..ControlClientVersion::default()
        });
    }

    Some(ControlClientVersion {
        latest_version: latest_version.to_string(),
        urgent_security_update: cap_version >= CAP_CLIENT_VERSION_URGENT_SECURITY_UPDATE
            && config.urgent_security_update,
        notify: config.notify,
        notify_url: config.notify_url.clone().unwrap_or_default(),
        notify_text: config.notify_text.clone().unwrap_or_default(),
        ..ControlClientVersion::default()
    })
}

fn deprecated_default_auto_update(
    cap_version: u32,
    attrs: &ControlNodeAttrsConfig,
) -> Option<bool> {
    (CAP_DEPRECATED_DEFAULT_AUTO_UPDATE..CAP_NODE_ATTR_DEFAULT_AUTO_UPDATE)
        .contains(&cap_version)
        .then_some(attrs.default_auto_update)
        .flatten()
}

fn hostinfo_ipn_version(hostinfo: &serde_json::Value) -> Option<&str> {
    hostinfo.get("IPNVersion")?.as_str()
}

fn compare_release_versions(current: &str, latest: &str) -> Option<Ordering> {
    let mut current = normalized_release_version(current)?;
    let mut latest = normalized_release_version(latest)?;
    let width = current.len().max(latest.len());
    current.resize(width, 0);
    latest.resize(width, 0);
    Some(current.cmp(&latest))
}

fn normalized_release_version(value: &str) -> Option<Vec<u64>> {
    let trimmed = value.trim();
    let core = trimmed
        .split_once('-')
        .map_or(trimmed, |(prefix, _)| prefix);
    let core = core.split_once('+').map_or(core, |(prefix, _)| prefix);
    let parts = core
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    (parts.len() >= 2).then_some(parts)
}

fn control_self_node_capabilities(
    cap_version: u32,
    attrs: &ControlNodeAttrsConfig,
) -> (Vec<String>, ControlNodeCapMap) {
    let mut cap_map = ControlNodeCapMap::new();

    if cap_version >= CAP_NODE_CAP_MAP {
        if let Some(display_name) = attrs.tailnet_display_name.as_deref() {
            cap_map.insert(
                "tailnet-display-name".to_string(),
                vec![json!(display_name)],
            );
        }
        if cap_version >= CAP_NODE_ATTR_DEFAULT_AUTO_UPDATE
            && let Some(default_auto_update) = attrs.default_auto_update
        {
            cap_map.insert(
                "default-auto-update".to_string(),
                vec![json!(default_auto_update)],
            );
        }
        if cap_version >= CAP_NODE_ATTR_MAX_KEY_DURATION
            && let Some(max_key_duration_secs) = attrs.max_key_duration_secs
        {
            cap_map.insert(
                "tailnet.maxKeyDuration".to_string(),
                vec![json!(max_key_duration_secs as f64)],
            );
        }
        if cap_version >= CAP_NODE_ATTR_CACHE_NETWORK_MAPS && attrs.cache_network_maps {
            cap_map.insert("cache-network-maps".to_string(), Vec::new());
        }
        if cap_version >= CAP_NODE_ATTR_DISABLE_HOSTS_FILE_UPDATES
            && attrs.disable_hosts_file_updates
        {
            cap_map.insert("disable-hosts-file-updates".to_string(), Vec::new());
        }
        if cap_version >= CAP_NODE_ATTR_FORCE_REGISTER_MAGICDNS_IPV4_ONLY
            && attrs.force_register_magicdns_ipv4_only
        {
            cap_map.insert("force-register-magicdns-ipv4-only".to_string(), Vec::new());
        }
        if cap_version >= CAP_NODE_ATTR_MAGICDNS_PEER_AAAA && attrs.magicdns_peer_aaaa {
            cap_map.insert("magicdns-aaaa".to_string(), Vec::new());
        }
        if cap_version >= CAP_NODE_ATTR_USER_DIAL_USE_ROUTES && attrs.user_dial_use_routes {
            cap_map.insert("user-dial-routes".to_string(), Vec::new());
        }
        if cap_version >= CAP_NODE_ATTR_DISABLE_CAPTIVE_PORTAL_DETECTION
            && attrs.disable_captive_portal_detection
        {
            cap_map.insert("disable-captive-portal-detection".to_string(), Vec::new());
        }
        if attrs.client_side_reachability {
            cap_map.insert("client-side-reachability".to_string(), Vec::new());
        }
    }

    let capabilities = if cap_version < CAP_NODE_CAP_MAP {
        cap_map
            .iter()
            .filter(|(_, values)| values.is_empty())
            .map(|(capability, _)| capability.clone())
            .collect()
    } else {
        Vec::new()
    };

    (capabilities, cap_map)
}

fn control_ip_candidate_from_config(config: &ControlDialCandidateConfig) -> ControlIpCandidate {
    ControlIpCandidate {
        ip: config.ip.clone().unwrap_or_default(),
        ace_host: config.ace_host.clone().unwrap_or_default(),
        dial_start_delay_sec: config.dial_start_delay_secs,
        dial_timeout_sec: config.dial_timeout_secs,
        priority: config.priority,
    }
}

fn public_base_url_ip(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let authority = after_scheme.split('/').next()?;
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);

    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return authority[1..end]
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_string());
    }

    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, port)| match port.parse::<u16>() {
            Ok(_) => host,
            Err(_) => authority,
        });
    host.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

fn to_control_filter_rules(
    rules: &[CompiledAclRule],
    grant_ip_rules: &[DomainGrantIpRule],
    cap_grant_rules: &[DomainCapGrantRule],
) -> Vec<ControlFilterRule> {
    let mut control_rules = rules
        .iter()
        .map(|rule| ControlFilterRule {
            src_ips: rule.src_ips.clone(),
            dst_ports: rule
                .destinations
                .iter()
                .flat_map(compiled_destination_to_control)
                .collect(),
            ip_proto: Vec::new(),
            cap_grant: Vec::new(),
        })
        .collect::<Vec<_>>();

    control_rules.extend(grant_ip_rules.iter().map(|rule| {
        ControlFilterRule {
            src_ips: rule.src_ips.clone(),
            dst_ports: rule
                .destinations
                .iter()
                .flat_map(compiled_destination_to_control)
                .collect(),
            ip_proto: rule.ip_protocols.clone(),
            cap_grant: Vec::new(),
        }
    }));

    control_rules.extend(cap_grant_rules.iter().map(|rule| {
        ControlFilterRule {
            src_ips: rule.src_ips.clone(),
            dst_ports: Vec::new(),
            ip_proto: Vec::new(),
            cap_grant: rule
                .grants
                .iter()
                .cloned()
                .map(to_control_cap_grant)
                .collect(),
        }
    }));

    control_rules
}

fn to_control_cap_grant(grant: DomainCapGrant) -> ControlCapGrant {
    ControlCapGrant {
        dsts: grant.destinations,
        cap_map: grant.cap_map,
    }
}

fn to_control_ssh_rule(rule: DomainSshRule, config: &AppConfig) -> ControlSshRule {
    ControlSshRule {
        principals: rule
            .principals
            .into_iter()
            .map(to_control_ssh_principal)
            .collect(),
        ssh_users: rule.ssh_users,
        action: Some(to_control_ssh_action(rule.action, config)),
        accept_env: rule.accept_env,
    }
}

fn to_control_ssh_principal(principal: DomainSshPrincipal) -> ControlSshPrincipal {
    match principal {
        DomainSshPrincipal::Any => ControlSshPrincipal {
            any: true,
            ..ControlSshPrincipal::default()
        },
        DomainSshPrincipal::NodeIp(node_ip) => ControlSshPrincipal {
            node_ip,
            ..ControlSshPrincipal::default()
        },
    }
}

fn to_control_ssh_action(action: DomainSshAction, config: &AppConfig) -> ControlSshAction {
    ControlSshAction {
        message: action.message.unwrap_or_default(),
        reject: action.reject,
        accept: action.accept,
        hold_and_delegate: if action.check {
            ssh_hold_and_delegate_url(config)
        } else {
            String::new()
        },
        session_duration: action
            .session_duration_secs
            .and_then(|secs| secs.checked_mul(1_000_000_000)),
        allow_agent_forwarding: action.allow_agent_forwarding,
        allow_local_port_forwarding: action.allow_local_port_forwarding,
        allow_remote_port_forwarding: action.allow_remote_port_forwarding,
    }
}

fn approved_ssh_action_from_check(action: &DomainSshAction) -> ControlSshAction {
    ControlSshAction {
        message: action.message.clone().unwrap_or_default(),
        accept: true,
        session_duration: action
            .session_duration_secs
            .and_then(|secs| secs.checked_mul(1_000_000_000)),
        allow_agent_forwarding: action.allow_agent_forwarding,
        allow_local_port_forwarding: action.allow_local_port_forwarding,
        allow_remote_port_forwarding: action.allow_remote_port_forwarding,
        ..ControlSshAction::default()
    }
}

fn rejected_ssh_action_from_check(action: &DomainSshAction) -> ControlSshAction {
    ControlSshAction {
        reject: true,
        session_duration: action
            .session_duration_secs
            .and_then(|secs| secs.checked_mul(1_000_000_000)),
        allow_agent_forwarding: action.allow_agent_forwarding,
        allow_local_port_forwarding: action.allow_local_port_forwarding,
        allow_remote_port_forwarding: action.allow_remote_port_forwarding,
        ..ControlSshAction::default()
    }
}

fn check_ssh_action_prompt(
    action: &DomainSshAction,
    config: &AppConfig,
    auth_id: &str,
) -> ControlSshAction {
    let mut response = to_control_ssh_action(action.clone(), config);
    response.hold_and_delegate = format!("{}?auth_id={auth_id}", ssh_hold_and_delegate_url(config));
    response
}

fn ssh_hold_and_delegate_url(config: &AppConfig) -> String {
    let base_url = config
        .server
        .public_base_url
        .as_deref()
        .map(str::trim)
        .map(|value| value.trim_end_matches('/'))
        .unwrap_or_default();
    format!(
        "{base_url}/machine/ssh/action/from/$SRC_NODE_ID/to/$DST_NODE_ID?ssh_user=$SSH_USER&local_user=$LOCAL_USER"
    )
}

fn ssh_action_binding(
    cap_version: u32,
    ssh_user: Option<&str>,
    local_user: Option<&str>,
) -> AppResult<Option<SshActionBinding>> {
    if cap_version < CAP_SSH_USERNAMES {
        return Ok(None);
    }

    let ssh_user = ssh_user
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            crate::error::AppError::Unauthorized(
                "SSH action request is missing ssh_user for a username-aware client".to_string(),
            )
        })?;
    let local_user = local_user
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            crate::error::AppError::Unauthorized(
                "SSH action request is missing local_user for a username-aware client".to_string(),
            )
        })?;

    Ok(Some(SshActionBinding {
        ssh_user: ssh_user.to_string(),
        local_user: local_user.to_string(),
    }))
}

fn compiled_destination_to_control(
    destination: &CompiledAclDestination,
) -> Vec<ControlNetPortRange> {
    destination
        .ports
        .iter()
        .map(|port| ControlNetPortRange {
            ip: destination.network.clone(),
            ports: to_control_port_range(port),
        })
        .collect()
}

fn to_control_port_range(port: &PolicyPortRange) -> ControlPortRange {
    ControlPortRange {
        first: port.first,
        last: port.last,
    }
}

fn register_response_for_record(record: &ControlNodeRecord) -> AppResult<RegisterResponse> {
    let identity = identity_view(record)?;
    Ok(RegisterResponse {
        user: identity.user,
        login: identity.login,
        machine_authorized: true,
        ..RegisterResponse::default()
    })
}

fn register_request_requires_interactive_auth(
    request: &RegisterRequest,
    existing_tag_source: Option<NodeTagSource>,
) -> bool {
    existing_tag_source.is_some()
        && request
            .auth
            .as_ref()
            .is_none_or(|auth| auth.auth_key.trim().is_empty())
        && request_has_explicit_request_tags(request)
        && existing_tag_source.is_none_or(|source| !source.is_server_forced())
}

fn request_has_explicit_request_tags(request: &RegisterRequest) -> bool {
    request
        .hostinfo
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .is_some_and(|hostinfo| hostinfo.contains_key("RequestTags"))
}

fn extract_followup_auth_id(followup: &str) -> AppResult<String> {
    let (_, rest) = followup
        .rsplit_once("/register/")
        .ok_or_else(|| crate::error::AppError::Unauthorized("invalid followup URL".to_string()))?;
    let auth_id = rest
        .split(['?', '#'])
        .next()
        .ok_or_else(|| {
            crate::error::AppError::Unauthorized(
                "invalid followup registration identifier".to_string(),
            )
        })?
        .trim();
    if auth_id.is_empty() {
        return Err(crate::error::AppError::Unauthorized(
            "invalid followup registration identifier".to_string(),
        ));
    }
    Ok(auth_id.to_string())
}

fn to_control_dns_config(dns: &DnsConfig) -> ControlDnsConfig {
    ControlDnsConfig {
        resolvers: dns
            .nameservers
            .iter()
            .map(|address| ControlDnsResolver {
                addr: address.clone(),
            })
            .collect(),
        domains: dns.search_domains.clone(),
        proxied: dns.magic_dns,
    }
}

fn default_domain(config: &AppConfig, dns: &DnsConfig) -> String {
    dns.base_domain
        .clone()
        .or_else(|| {
            config.server.public_base_url.as_deref().and_then(|url| {
                url.split("://")
                    .nth(1)
                    .and_then(|rest| rest.split('/').next())
                    .map(str::to_string)
            })
        })
        .unwrap_or_else(|| "rscale.local".to_string())
}

fn fqdn(hostname: &str, dns: &DnsConfig) -> String {
    match dns.base_domain.as_deref() {
        Some(base_domain) if dns.magic_dns => format!("{hostname}.{base_domain}."),
        _ => format!("{hostname}."),
    }
}

fn approved_route_map(routes: &[crate::domain::Route]) -> BTreeMap<u64, Vec<String>> {
    let mut grouped = BTreeMap::<u64, Vec<String>>::new();
    for route in routes {
        grouped
            .entry(route.node_id)
            .or_default()
            .push(route.prefix.clone());
    }
    grouped
}

fn identity_view(record: &ControlNodeRecord) -> AppResult<IdentityView> {
    if !record.node.tags.is_empty() {
        return local_identity_view(record);
    }

    if let Some(principal) = &record.principal {
        let created = format_unix_secs(principal.created_at_unix_secs)?;
        let display_name = if principal.display_name.trim().is_empty() {
            principal.login_name.clone()
        } else {
            principal.display_name.clone()
        };
        return Ok(IdentityView {
            user: ControlUser {
                id: principal.id,
                display_name: display_name.clone(),
                created,
                ..ControlUser::default()
            },
            login: ControlLogin {
                id: principal.id,
                provider: principal.provider.clone(),
                login_name: principal.login_name.clone(),
                display_name: display_name.clone(),
                ..ControlLogin::default()
            },
            profile: ControlUserProfile {
                id: principal.id,
                login_name: principal.login_name.clone(),
                display_name,
                groups: principal.groups.clone(),
                ..ControlUserProfile::default()
            },
        });
    }

    local_identity_view(record)
}

fn local_identity_view(record: &ControlNodeRecord) -> AppResult<IdentityView> {
    let id = LOCAL_IDENTITY_OFFSET.saturating_add(record.node.id);
    let display_name = record.node.name.clone();
    let login_name = format!("{}@local", record.node.hostname);

    Ok(IdentityView {
        user: ControlUser {
            id,
            display_name: display_name.clone(),
            created: format_unix_secs(record.created_at_unix_secs)?,
            ..ControlUser::default()
        },
        login: ControlLogin {
            id,
            provider: "rscale".to_string(),
            login_name: login_name.clone(),
            display_name: display_name.clone(),
            ..ControlLogin::default()
        },
        profile: ControlUserProfile {
            id,
            login_name,
            display_name,
            ..ControlUserProfile::default()
        },
    })
}

fn is_online(config: &AppConfig, node: &ControlNodeRecord) -> bool {
    match node.node.status {
        NodeStatus::Disabled | NodeStatus::Expired => false,
        NodeStatus::Online | NodeStatus::Pending | NodeStatus::Offline => {
            let Some(last_seen) = node.node.last_seen_unix_secs else {
                return false;
            };

            let now = OffsetDateTime::now_utc().unix_timestamp();
            let Ok(last_seen) = i64::try_from(last_seen) else {
                return false;
            };
            let Ok(online_window_secs) = i64::try_from(config.network.node_online_window_secs)
            else {
                return false;
            };
            let within_window = now
                .checked_sub(last_seen)
                .is_some_and(|age| age <= online_window_secs);
            let session_valid = node
                .session_expires_at_unix_secs
                .and_then(|value| i64::try_from(value).ok())
                .is_none_or(|value| value > now);

            within_window && session_valid
        }
    }
}

fn now_rfc3339() -> AppResult<String> {
    OffsetDateTime::now_utc().format(&Rfc3339).map_err(|err| {
        crate::error::AppError::Bootstrap(format!("failed to format timestamp: {err}"))
    })
}

fn now_unix_secs() -> AppResult<u64> {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).map_err(|_| {
        crate::error::AppError::Bootstrap(
            "current time cannot be represented as a positive Unix timestamp".to_string(),
        )
    })
}

fn format_unix_secs(value: u64) -> AppResult<String> {
    let timestamp = i64::try_from(value).map_err(|_| {
        crate::error::AppError::Bootstrap(format!("timestamp {value} cannot be represented as i64"))
    })?;
    let timestamp = OffsetDateTime::from_unix_timestamp(timestamp).map_err(|err| {
        crate::error::AppError::Bootstrap(format!("invalid timestamp {value}: {err}"))
    })?;
    timestamp.format(&Rfc3339).map_err(|err| {
        crate::error::AppError::Bootstrap(format!("failed to format timestamp: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn node(id: u64, name: &str, user: u64) -> ControlNode {
        ControlNode {
            id,
            stable_id: format!("stable-{id}"),
            name: name.to_string(),
            user,
            key: format!("nodekey:{id}"),
            machine: format!("mkey:{id}"),
            addresses: vec![format!("100.64.0.{id}/32")],
            allowed_ips: vec![format!("100.64.0.{id}/32")],
            ..ControlNode::default()
        }
    }

    fn register_request(hostinfo: serde_json::Value) -> RegisterRequest {
        RegisterRequest {
            version: 1,
            node_key: "nodekey:1".to_string(),
            old_node_key: String::new(),
            nl_key: String::new(),
            auth: None,
            expiry: String::new(),
            followup: String::new(),
            hostinfo: Some(hostinfo),
            ephemeral: false,
            node_key_signature: None,
            tailnet: String::new(),
        }
    }

    #[test]
    fn register_request_requires_interactive_auth_for_existing_node_with_request_tags() {
        let request = register_request(json!({
            "Hostname": "workstation",
            "RequestTags": ["tag:prod"]
        }));

        assert!(register_request_requires_interactive_auth(
            &request,
            Some(NodeTagSource::None),
        ));
    }

    #[test]
    fn register_request_requires_interactive_auth_for_existing_node_with_empty_request_tags() {
        let request = register_request(json!({
            "Hostname": "workstation",
            "RequestTags": []
        }));

        assert!(register_request_requires_interactive_auth(
            &request,
            Some(NodeTagSource::Request),
        ));
    }

    #[test]
    fn register_request_does_not_require_interactive_auth_for_existing_node_without_request_tags() {
        let request = register_request(json!({
            "Hostname": "workstation"
        }));

        assert!(!register_request_requires_interactive_auth(
            &request,
            Some(NodeTagSource::None),
        ));
    }

    #[test]
    fn register_request_does_not_require_interactive_auth_when_auth_key_is_present() {
        let request = RegisterRequest {
            auth: Some(crate::protocol::types::RegisterResponseAuth {
                auth_key: "tskey-auth-123".to_string(),
            }),
            ..register_request(json!({
                "Hostname": "workstation",
                "RequestTags": []
            }))
        };

        assert!(!register_request_requires_interactive_auth(
            &request,
            Some(NodeTagSource::None),
        ));
    }

    #[test]
    fn register_request_does_not_require_interactive_auth_for_server_managed_tags() {
        let request = register_request(json!({
            "Hostname": "workstation",
            "RequestTags": ["tag:prod"]
        }));

        assert!(!register_request_requires_interactive_auth(
            &request,
            Some(NodeTagSource::AuthKey),
        ));
        assert!(!register_request_requires_interactive_auth(
            &request,
            Some(NodeTagSource::Admin),
        ));
    }

    #[test]
    fn incremental_map_response_emits_peer_deltas_and_omits_unchanged_fields() -> TestResult {
        let previous = MapResponse {
            node: Some(ControlNode {
                cap: 36,
                ..node(10, "self.", 1)
            }),
            peers: vec![node(1, "one.", 2), node(2, "two.", 3)],
            user_profiles: vec![
                ControlUserProfile {
                    id: 2,
                    login_name: "one@example.com".to_string(),
                    ..ControlUserProfile::default()
                },
                ControlUserProfile {
                    id: 3,
                    login_name: "two@example.com".to_string(),
                    ..ControlUserProfile::default()
                },
            ],
            domain: "example.com".to_string(),
            seq: 1,
            ..MapResponse::default()
        };
        let current = MapResponse {
            node: Some(ControlNode {
                cap: 36,
                ..node(10, "self.", 1)
            }),
            peers: vec![
                ControlNode {
                    endpoints: vec!["198.51.100.10:41641".to_string()],
                    online: Some(true),
                    last_seen: "2026-04-16T00:00:00Z".to_string(),
                    ..node(1, "one.", 2)
                },
                node(3, "three.", 4),
            ],
            user_profiles: vec![
                ControlUserProfile {
                    id: 2,
                    login_name: "one@example.com".to_string(),
                    ..ControlUserProfile::default()
                },
                ControlUserProfile {
                    id: 4,
                    login_name: "three@example.com".to_string(),
                    ..ControlUserProfile::default()
                },
            ],
            domain: "example.com".to_string(),
            seq: 2,
            control_time: Some("2026-04-16T00:00:00Z".to_string()),
            ..MapResponse::default()
        };

        let delta = incremental_map_response(&previous, &current)
            .ok_or_else(|| std::io::Error::other("delta should exist"))?;
        assert_eq!(delta.seq, 2);
        assert!(delta.node.is_none());
        assert_eq!(delta.peers_changed.len(), 1);
        assert_eq!(delta.peers_changed[0].id, 3);
        assert_eq!(delta.peers_removed, vec![2]);
        assert_eq!(delta.peers_changed_patch.len(), 1);
        assert_eq!(delta.peers_changed_patch[0].node_id, 1);
        assert_eq!(
            delta.peers_changed_patch[0].endpoints,
            vec!["198.51.100.10:41641".to_string()]
        );
        assert_eq!(delta.peers_changed_patch[0].online, Some(true));
        assert_eq!(delta.user_profiles.len(), 1);
        assert_eq!(delta.user_profiles[0].id, 4);
        assert!(delta.domain.is_empty());
        assert!(delta.peers.is_empty());
        Ok(())
    }

    #[test]
    fn incremental_map_response_uses_legacy_online_and_last_seen_changes_for_older_clients()
    -> TestResult {
        let previous = MapResponse {
            node: Some(ControlNode {
                cap: 16,
                ..node(10, "self.", 1)
            }),
            peers: vec![ControlNode {
                online: Some(false),
                ..node(1, "one.", 2)
            }],
            ..MapResponse::default()
        };
        let current = MapResponse {
            node: Some(ControlNode {
                cap: 16,
                ..node(10, "self.", 1)
            }),
            peers: vec![ControlNode {
                online: Some(true),
                last_seen: "2026-04-16T00:00:00Z".to_string(),
                ..node(1, "one.", 2)
            }],
            seq: 4,
            ..MapResponse::default()
        };

        let delta = incremental_map_response(&previous, &current)
            .ok_or_else(|| std::io::Error::other("delta should exist"))?;
        assert!(delta.peers_changed.is_empty());
        assert!(delta.peers_changed_patch.is_empty());
        assert_eq!(delta.online_change.get(&1), Some(&true));
        assert_eq!(delta.peer_seen_change.get(&1), Some(&true));
        Ok(())
    }

    #[test]
    fn incremental_map_response_returns_none_for_identical_state() {
        let current = MapResponse {
            node: Some(ControlNode {
                cap: 36,
                ..node(10, "self.", 1)
            }),
            peers: vec![node(1, "one.", 2)],
            seq: 3,
            ..MapResponse::default()
        };

        assert!(incremental_map_response(&current, &current).is_none());
    }

    #[test]
    fn incremental_map_response_emits_display_message_patch_and_control_dial_plan_update()
    -> TestResult {
        let previous = MapResponse {
            node: Some(ControlNode {
                cap: 117,
                ..node(10, "self.", 1)
            }),
            control_dial_plan: Some(ControlDialPlan::default()),
            ..MapResponse::default()
        };
        let current = MapResponse {
            node: Some(ControlNode {
                cap: 117,
                ..node(10, "self.", 1)
            }),
            display_messages: Some(BTreeMap::from([(
                "maintenance".to_string(),
                Some(ControlDisplayMessage {
                    title: "Maintenance".to_string(),
                    text: "Scheduled control-plane work".to_string(),
                    severity: ControlDisplayMessageSeverity::Medium,
                    impacts_connectivity: false,
                    primary_action: None,
                }),
            )])),
            control_dial_plan: Some(ControlDialPlan {
                candidates: vec![ControlIpCandidate {
                    ip: "203.0.113.10".to_string(),
                    dial_timeout_sec: Some(5.0),
                    priority: 10,
                    ..ControlIpCandidate::default()
                }],
            }),
            seq: 5,
            ..MapResponse::default()
        };

        let delta = incremental_map_response(&previous, &current)
            .ok_or_else(|| std::io::Error::other("delta should exist"))?;
        assert!(delta.health.is_none());
        assert!(delta.display_messages.is_some());
        assert!(delta.control_dial_plan.is_some());
        assert_eq!(
            delta
                .display_messages
                .as_ref()
                .and_then(|messages| messages.get("maintenance")),
            Some(&Some(ControlDisplayMessage {
                title: "Maintenance".to_string(),
                text: "Scheduled control-plane work".to_string(),
                severity: ControlDisplayMessageSeverity::Medium,
                impacts_connectivity: false,
                primary_action: None,
            }))
        );
        Ok(())
    }

    #[test]
    fn incremental_map_response_clears_display_messages_with_star_patch() -> TestResult {
        let previous = MapResponse {
            node: Some(ControlNode {
                cap: 117,
                ..node(10, "self.", 1)
            }),
            display_messages: Some(BTreeMap::from([(
                "maintenance".to_string(),
                Some(ControlDisplayMessage {
                    title: "Maintenance".to_string(),
                    text: "Scheduled control-plane work".to_string(),
                    severity: ControlDisplayMessageSeverity::Medium,
                    impacts_connectivity: false,
                    primary_action: None,
                }),
            )])),
            ..MapResponse::default()
        };
        let current = MapResponse {
            node: Some(ControlNode {
                cap: 117,
                ..node(10, "self.", 1)
            }),
            display_messages: None,
            seq: 6,
            ..MapResponse::default()
        };

        let delta = incremental_map_response(&previous, &current)
            .ok_or_else(|| std::io::Error::other("delta should exist"))?;
        assert_eq!(
            delta.display_messages,
            Some(BTreeMap::from([("*".to_string(), None)]))
        );
        Ok(())
    }

    #[test]
    fn control_dial_plan_infers_ip_candidate_from_public_base_url() -> TestResult {
        let mut config = AppConfig::default();
        config.server.public_base_url = Some("https://203.0.113.10".to_string());

        let plan = control_dial_plan(44, &config)
            .ok_or_else(|| std::io::Error::other("dial plan should be present"))?;
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].ip, "203.0.113.10");
        Ok(())
    }

    #[test]
    fn incremental_map_response_emits_pop_browser_url_and_collect_services_changes() -> TestResult {
        let previous = MapResponse {
            node: Some(ControlNode {
                cap: 36,
                ..node(10, "self.", 1)
            }),
            seq: 6,
            ..MapResponse::default()
        };
        let current = MapResponse {
            node: Some(ControlNode {
                cap: 36,
                ..node(10, "self.", 1)
            }),
            pop_browser_url: "https://login.rscale.example.com/device-action".to_string(),
            collect_services: Some(true),
            seq: 7,
            ..MapResponse::default()
        };

        let delta = incremental_map_response(&previous, &current)
            .ok_or_else(|| std::io::Error::other("delta should exist"))?;
        assert_eq!(
            delta.pop_browser_url,
            "https://login.rscale.example.com/device-action"
        );
        assert_eq!(delta.collect_services, Some(true));
        Ok(())
    }

    #[test]
    fn incremental_map_response_emits_ssh_policy_clear_update() -> TestResult {
        let previous = MapResponse {
            node: Some(ControlNode {
                cap: 36,
                ..node(10, "self.", 1)
            }),
            ssh_policy: Some(ControlSshPolicy {
                rules: vec![ControlSshRule {
                    principals: vec![ControlSshPrincipal {
                        node_ip: "100.64.0.20".to_string(),
                        ..ControlSshPrincipal::default()
                    }],
                    ssh_users: BTreeMap::from([("*".to_string(), "=".to_string())]),
                    action: Some(ControlSshAction {
                        accept: true,
                        ..ControlSshAction::default()
                    }),
                    accept_env: vec!["TERM".to_string()],
                }],
            }),
            seq: 7,
            ..MapResponse::default()
        };
        let current = MapResponse {
            node: Some(ControlNode {
                cap: 36,
                ..node(10, "self.", 1)
            }),
            ssh_policy: Some(ControlSshPolicy::default()),
            seq: 8,
            ..MapResponse::default()
        };

        let delta = incremental_map_response(&previous, &current)
            .ok_or_else(|| std::io::Error::other("delta should exist"))?;
        assert_eq!(delta.ssh_policy, Some(ControlSshPolicy::default()));
        Ok(())
    }

    #[test]
    fn control_self_node_capabilities_emits_cap_map_for_supported_clients() {
        let attrs = ControlNodeAttrsConfig {
            tailnet_display_name: Some("Example Tailnet".to_string()),
            default_auto_update: Some(true),
            max_key_duration_secs: Some(2_592_000),
            cache_network_maps: true,
            disable_hosts_file_updates: true,
            force_register_magicdns_ipv4_only: true,
            magicdns_peer_aaaa: true,
            user_dial_use_routes: true,
            disable_captive_portal_detection: true,
            client_side_reachability: true,
        };

        let (capabilities, cap_map) = control_self_node_capabilities(135, &attrs);
        assert!(capabilities.is_empty());
        assert_eq!(
            cap_map.get("tailnet-display-name"),
            Some(&vec![json!("Example Tailnet")])
        );
        assert_eq!(cap_map.get("default-auto-update"), Some(&vec![json!(true)]));
        assert_eq!(
            cap_map.get("tailnet.maxKeyDuration"),
            Some(&vec![json!(2_592_000_f64)])
        );
        assert!(cap_map.contains_key("cache-network-maps"));
        assert!(cap_map.contains_key("disable-hosts-file-updates"));
        assert!(cap_map.contains_key("force-register-magicdns-ipv4-only"));
        assert!(cap_map.contains_key("magicdns-aaaa"));
        assert!(cap_map.contains_key("user-dial-routes"));
        assert!(cap_map.contains_key("disable-captive-portal-detection"));
        assert!(cap_map.contains_key("client-side-reachability"));
    }

    #[test]
    fn control_self_node_capabilities_gate_newer_attrs_by_capability_version() {
        let attrs = ControlNodeAttrsConfig {
            default_auto_update: Some(true),
            cache_network_maps: true,
            magicdns_peer_aaaa: true,
            ..ControlNodeAttrsConfig::default()
        };

        let (_, cap_map) = control_self_node_capabilities(116, &attrs);
        assert!(!cap_map.contains_key("default-auto-update"));
        assert!(!cap_map.contains_key("cache-network-maps"));
        assert!(cap_map.contains_key("magicdns-aaaa"));
    }

    #[test]
    fn control_client_version_marks_outdated_client_and_sets_notification_fields() -> TestResult {
        let config = ControlClientVersionConfig {
            latest_version: Some("1.82.0".to_string()),
            urgent_security_update: true,
            notify: true,
            notify_url: Some("https://pkgs.tailscale.com/stable/".to_string()),
            notify_text: Some("Upgrade available".to_string()),
        };

        let version =
            control_client_version(79, Some(&json!({"IPNVersion": "1.80.2-tabcdef"})), &config)
                .ok_or_else(|| std::io::Error::other("client version should be present"))?;

        assert!(!version.running_latest);
        assert_eq!(version.latest_version, "1.82.0");
        assert!(version.urgent_security_update);
        assert!(version.notify);
        assert_eq!(version.notify_url, "https://pkgs.tailscale.com/stable/");
        assert_eq!(version.notify_text, "Upgrade available");
        Ok(())
    }

    #[test]
    fn control_client_version_marks_current_client_as_running_latest() -> TestResult {
        let config = ControlClientVersionConfig {
            latest_version: Some("1.82.0".to_string()),
            ..ControlClientVersionConfig::default()
        };

        let version = control_client_version(73, Some(&json!({"IPNVersion": "1.82.0"})), &config)
            .ok_or_else(|| std::io::Error::other("client version should be present"))?;

        assert!(version.running_latest);
        assert!(version.latest_version.is_empty());
        assert!(!version.notify);
        Ok(())
    }

    #[test]
    fn control_client_version_omits_response_when_hostinfo_lacks_parseable_version() {
        let config = ControlClientVersionConfig {
            latest_version: Some("1.82.0".to_string()),
            ..ControlClientVersionConfig::default()
        };

        assert!(control_client_version(73, Some(&json!({"IPNVersion": "dev"})), &config).is_none());
        assert!(control_client_version(73, None, &config).is_none());
    }

    #[test]
    fn deprecated_default_auto_update_only_applies_to_pre_capmap_clients() {
        let attrs = ControlNodeAttrsConfig {
            default_auto_update: Some(true),
            ..ControlNodeAttrsConfig::default()
        };

        assert_eq!(deprecated_default_auto_update(82, &attrs), None);
        assert_eq!(deprecated_default_auto_update(83, &attrs), Some(true));
        assert_eq!(deprecated_default_auto_update(130, &attrs), Some(true));
        assert_eq!(deprecated_default_auto_update(131, &attrs), None);
    }

    #[test]
    fn compare_release_versions_treats_missing_patch_as_zero() {
        assert_eq!(
            compare_release_versions("1.82", "1.82.0"),
            Some(Ordering::Equal)
        );
    }

    #[test]
    fn control_pop_browser_url_requires_supported_client_version() {
        let mut config = AppConfig::default();
        config.control.pop_browser_url =
            Some("https://login.rscale.example.com/device-action".to_string());

        assert!(control_pop_browser_url(28, &config).is_empty());
        assert_eq!(
            control_pop_browser_url(29, &config),
            "https://login.rscale.example.com/device-action"
        );
    }

    #[test]
    fn control_ssh_policy_requires_supported_client_version() -> TestResult {
        let subject = crate::domain::Node {
            id: 10,
            stable_id: "stable-10".to_string(),
            name: "server".to_string(),
            hostname: "server".to_string(),
            auth_key_id: None,
            principal_id: None,
            ipv4: Some("100.64.0.10".to_string()),
            ipv6: None,
            status: crate::domain::NodeStatus::Online,
            tags: vec!["tag:server".to_string()],
            tag_source: NodeTagSource::Request,
            last_seen_unix_secs: None,
        };
        let peer = crate::domain::Node {
            id: 11,
            stable_id: "stable-11".to_string(),
            name: "client".to_string(),
            hostname: "client".to_string(),
            auth_key_id: None,
            principal_id: None,
            ipv4: Some("100.64.0.11".to_string()),
            ipv6: None,
            status: crate::domain::NodeStatus::Online,
            tags: vec!["tag:client".to_string()],
            tag_source: NodeTagSource::Request,
            last_seen_unix_secs: None,
        };
        let policy = crate::domain::AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: crate::domain::AutoApproverPolicy::default(),
            ssh_rules: vec![crate::domain::SshPolicyRule {
                action: crate::domain::SshPolicyAction::Accept,
                sources: vec!["tag:client".to_string()],
                destinations: vec!["tag:server".to_string()],
                ssh_users: BTreeMap::from([("*".to_string(), "=".to_string())]),
                accept_env: vec!["TERM".to_string()],
                message: Some("SSH access granted".to_string()),
                allow_agent_forwarding: true,
                allow_local_port_forwarding: true,
                allow_remote_port_forwarding: true,
                session_duration_secs: Some(3600),
                check_period_secs: None,
            }],
        };
        let config = AppConfig::default();

        assert!(
            control_ssh_policy(
                26,
                &policy,
                &subject,
                &[peer.clone(), subject.clone()],
                &[],
                &config,
                false,
            )?
            .is_none()
        );

        let ssh_policy = control_ssh_policy(
            27,
            &policy,
            &subject,
            &[peer, subject.clone()],
            &[],
            &config,
            false,
        )?
        .ok_or_else(|| std::io::Error::other("ssh policy should be present"))?;
        assert_eq!(ssh_policy.rules.len(), 1);
        assert_eq!(
            ssh_policy.rules[0].principals,
            vec![ControlSshPrincipal {
                node_ip: "100.64.0.11".to_string(),
                ..ControlSshPrincipal::default()
            }]
        );
        assert_eq!(
            ssh_policy.rules[0]
                .action
                .as_ref()
                .and_then(|action| action.session_duration),
            Some(3_600_000_000_000)
        );
        assert_eq!(
            ssh_policy.rules[0]
                .action
                .as_ref()
                .map(|action| action.hold_and_delegate.as_str()),
            Some("")
        );
        Ok(())
    }

    #[test]
    fn control_ssh_policy_includes_hold_and_delegate_for_check_rules() -> TestResult {
        let mut config = AppConfig::default();
        config.server.public_base_url = Some("https://control.rscale.example.com".to_string());
        let subject = crate::domain::Node {
            id: 10,
            stable_id: "stable-10".to_string(),
            name: "server".to_string(),
            hostname: "server".to_string(),
            auth_key_id: None,
            principal_id: None,
            ipv4: Some("100.64.0.10".to_string()),
            ipv6: None,
            status: crate::domain::NodeStatus::Online,
            tags: vec!["tag:server".to_string()],
            tag_source: NodeTagSource::Request,
            last_seen_unix_secs: None,
        };
        let peer = crate::domain::Node {
            id: 11,
            stable_id: "stable-11".to_string(),
            name: "client".to_string(),
            hostname: "client".to_string(),
            auth_key_id: None,
            principal_id: None,
            ipv4: Some("100.64.0.11".to_string()),
            ipv6: None,
            status: crate::domain::NodeStatus::Online,
            tags: vec!["tag:client".to_string()],
            tag_source: NodeTagSource::Request,
            last_seen_unix_secs: None,
        };
        let policy = crate::domain::AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: crate::domain::AutoApproverPolicy::default(),
            ssh_rules: vec![crate::domain::SshPolicyRule {
                action: crate::domain::SshPolicyAction::Check,
                sources: vec!["tag:client".to_string()],
                destinations: vec!["tag:server".to_string()],
                ssh_users: BTreeMap::from([("*".to_string(), "=".to_string())]),
                accept_env: Vec::new(),
                message: None,
                allow_agent_forwarding: true,
                allow_local_port_forwarding: true,
                allow_remote_port_forwarding: true,
                session_duration_secs: None,
                check_period_secs: Some(3_600),
            }],
        };

        let ssh_policy = control_ssh_policy(
            27,
            &policy,
            &subject,
            &[peer, subject.clone()],
            &[],
            &config,
            true,
        )?
        .ok_or_else(|| std::io::Error::other("ssh policy should be present"))?;

        assert_eq!(
            ssh_policy.rules[0]
                .action
                .as_ref()
                .map(|action| action.hold_and_delegate.as_str()),
            Some(
                "https://control.rscale.example.com/machine/ssh/action/from/$SRC_NODE_ID/to/$DST_NODE_ID?ssh_user=$SSH_USER&local_user=$LOCAL_USER"
            )
        );
        Ok(())
    }

    #[test]
    fn control_ssh_policy_requires_oidc_for_check_rules() -> TestResult {
        let mut config = AppConfig::default();
        config.server.public_base_url = Some("https://control.rscale.example.com".to_string());
        let subject = crate::domain::Node {
            id: 10,
            stable_id: "stable-10".to_string(),
            name: "server".to_string(),
            hostname: "server".to_string(),
            auth_key_id: None,
            principal_id: None,
            ipv4: Some("100.64.0.10".to_string()),
            ipv6: None,
            status: crate::domain::NodeStatus::Online,
            tags: vec!["tag:server".to_string()],
            tag_source: NodeTagSource::Request,
            last_seen_unix_secs: None,
        };
        let policy = crate::domain::AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: crate::domain::AutoApproverPolicy::default(),
            ssh_rules: vec![crate::domain::SshPolicyRule {
                action: crate::domain::SshPolicyAction::Check,
                sources: vec!["*".to_string()],
                destinations: vec!["tag:server".to_string()],
                ssh_users: BTreeMap::from([("*".to_string(), "=".to_string())]),
                accept_env: Vec::new(),
                message: None,
                allow_agent_forwarding: true,
                allow_local_port_forwarding: true,
                allow_remote_port_forwarding: true,
                session_duration_secs: None,
                check_period_secs: Some(3_600),
            }],
        };

        let error = match control_ssh_policy(
            27,
            &policy,
            &subject,
            std::slice::from_ref(&subject),
            &[],
            &config,
            false,
        ) {
            Ok(_) => {
                return Err(std::io::Error::other("ssh check rules should require oidc").into());
            }
            Err(err) => err,
        };
        assert!(error.to_string().contains("OIDC"));
        Ok(())
    }

    #[test]
    fn ssh_action_binding_requires_user_fields_for_username_aware_clients() -> TestResult {
        let error = match ssh_action_binding(43, Some("alice"), None) {
            Ok(_) => return Err(std::io::Error::other("binding should reject").into()),
            Err(err) => err,
        };
        assert!(error.to_string().contains("local_user"));
        Ok(())
    }

    #[test]
    fn ssh_action_binding_is_optional_for_legacy_clients() -> TestResult {
        assert!(ssh_action_binding(42, None, None)?.is_none());
        Ok(())
    }

    #[test]
    fn control_filter_rules_include_cap_grants() {
        let rules = to_control_filter_rules(
            &[CompiledAclRule {
                src_ips: vec!["100.64.0.10".to_string()],
                destinations: vec![CompiledAclDestination {
                    network: "100.64.0.20".to_string(),
                    ports: vec![PolicyPortRange {
                        first: 443,
                        last: 443,
                    }],
                }],
            }],
            &[],
            &[DomainCapGrantRule {
                src_ips: vec!["100.64.0.10".to_string()],
                grants: vec![DomainCapGrant {
                    destinations: vec!["100.64.0.20".to_string()],
                    cap_map: BTreeMap::from([(
                        "tailscale.com/cap/webui".to_string(),
                        Some(vec![json!({ "ports": [443] })]),
                    )]),
                }],
            }],
        );

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].dst_ports.len(), 1);
        assert!(rules[0].ip_proto.is_empty());
        assert!(rules[0].cap_grant.is_empty());
        assert!(rules[1].dst_ports.is_empty());
        assert!(rules[1].ip_proto.is_empty());
        assert_eq!(
            rules[1].cap_grant,
            vec![ControlCapGrant {
                dsts: vec!["100.64.0.20".to_string()],
                cap_map: BTreeMap::from([(
                    "tailscale.com/cap/webui".to_string(),
                    Some(vec![json!({ "ports": [443] })]),
                )]),
            }]
        );
    }

    #[test]
    fn control_filter_rules_preserve_null_companion_caps() {
        let rules = to_control_filter_rules(
            &[],
            &[],
            &[DomainCapGrantRule {
                src_ips: vec!["100.64.0.20".to_string()],
                grants: vec![DomainCapGrant {
                    destinations: vec!["100.64.0.10".to_string()],
                    cap_map: BTreeMap::from([("tailscale.com/cap/drive-sharer".to_string(), None)]),
                }],
            }],
        );

        assert_eq!(
            rules,
            vec![ControlFilterRule {
                src_ips: vec!["100.64.0.20".to_string()],
                dst_ports: Vec::new(),
                ip_proto: Vec::new(),
                cap_grant: vec![ControlCapGrant {
                    dsts: vec!["100.64.0.10".to_string()],
                    cap_map: BTreeMap::from([
                        ("tailscale.com/cap/drive-sharer".to_string(), None,)
                    ]),
                }],
            }]
        );
    }

    #[test]
    fn control_filter_rules_include_grant_ip_protocols() {
        let rules = to_control_filter_rules(
            &[],
            &[DomainGrantIpRule {
                src_ips: vec!["100.64.0.10".to_string()],
                destinations: vec![CompiledAclDestination {
                    network: "10.20.0.0/24".to_string(),
                    ports: vec![PolicyPortRange {
                        first: 443,
                        last: 443,
                    }],
                }],
                ip_protocols: vec![6],
            }],
            &[],
        );

        assert_eq!(
            rules,
            vec![ControlFilterRule {
                src_ips: vec!["100.64.0.10".to_string()],
                dst_ports: vec![ControlNetPortRange {
                    ip: "10.20.0.0/24".to_string(),
                    ports: ControlPortRange {
                        first: 443,
                        last: 443,
                    },
                }],
                ip_proto: vec![6],
                cap_grant: Vec::new(),
            }]
        );
    }
}
