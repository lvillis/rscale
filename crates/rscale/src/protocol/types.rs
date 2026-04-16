use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EarlyNoise {
    pub node_key_challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct OverTlsPublicKeyResponse {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub legacy_public_key: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DerpAdmitClientRequest {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node_public: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DerpAdmitClientResponse {
    pub allow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterResponseAuth {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterRequest {
    pub version: u32,
    pub node_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub old_node_key: String,
    #[serde(rename = "NLKey")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nl_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<RegisterResponseAuth>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expiry: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub followup: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostinfo: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ephemeral: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_key_signature: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tailnet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterResponse {
    #[serde(default)]
    pub user: ControlUser,
    #[serde(default)]
    pub login: ControlLogin,
    #[serde(default, skip_serializing_if = "is_false")]
    pub node_key_expired: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub machine_authorized: bool,
    #[serde(rename = "AuthURL")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_key_signature: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlUser {
    pub id: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    #[serde(rename = "ProfilePicURL")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile_pic_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlLogin {
    pub id: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provider: String,
    #[serde(rename = "LoginName")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub login_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    #[serde(rename = "ProfilePicURL")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile_pic_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct MapRequest {
    pub version: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compress: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub keep_alive: bool,
    pub node_key: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub disco_key: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub stream: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostinfo: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub map_session_handle: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub map_session_seq: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoint_types: Vec<i32>,
    #[serde(rename = "TKAHead")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tka_head: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub omit_peers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct MapResponse {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub map_session_handle: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub seq: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub keep_alive: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pop_browser_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<ControlNode>,
    #[serde(rename = "DERPMap")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp_map: Option<ControlDerpMap>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<ControlNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers_changed: Vec<ControlNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers_removed: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers_changed_patch: Vec<ControlPeerChange>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub peer_seen_change: BTreeMap<u64, bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub online_change: BTreeMap<u64, bool>,
    #[serde(rename = "DNSConfig")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_config: Option<ControlDnsConfig>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collect_services: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_filter: Option<Vec<ControlFilterRule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_filters: Option<BTreeMap<String, Vec<ControlFilterRule>>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_profiles: Vec<ControlUserProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_messages: Option<BTreeMap<String, Option<ControlDisplayMessage>>>,
    #[serde(rename = "SSHPolicy")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_policy: Option<ControlSshPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_dial_plan: Option<ControlDialPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<ControlClientVersion>,
    #[serde(rename = "DefaultAutoUpdate")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deprecated_default_auto_update: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlNode {
    pub id: u64,
    #[serde(rename = "StableID")]
    pub stable_id: String,
    pub name: String,
    pub user: u64,
    pub key: String,
    #[serde(rename = "KeyExpiry")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_expiry: String,
    pub machine: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub disco_key: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    #[serde(rename = "AllowedIPs")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    #[serde(rename = "DERP", default, skip_serializing_if = "String::is_empty")]
    pub legacy_derp_string: String,
    #[serde(rename = "HomeDERP")]
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub home_derp: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostinfo: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created: String,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cap: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(rename = "PrimaryRoutes")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub primary_routes: Vec<String>,
    #[serde(rename = "LastSeen")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_seen: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub machine_authorized: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(rename = "CapMap")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cap_map: BTreeMap<String, Vec<serde_json::Value>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub expired: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlPeerChange {
    #[serde(rename = "NodeID")]
    pub node_id: u64,
    #[serde(rename = "DERPRegion")]
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub derp_region: i32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub cap: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key: String,
    #[serde(rename = "DiscoKey")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub disco_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    #[serde(rename = "LastSeen")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_seen: String,
    #[serde(rename = "KeyExpiry")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_expiry: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlDisplayMessage {
    pub title: String,
    pub text: String,
    pub severity: ControlDisplayMessageSeverity,
    #[serde(default, skip_serializing_if = "is_false")]
    pub impacts_connectivity: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_action: Option<ControlDisplayMessageAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlDisplayMessageAction {
    pub url: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ControlSshPolicy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ControlSshRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ControlSshRule {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principals: Vec<ControlSshPrincipal>,
    #[serde(rename = "sshUsers")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ssh_users: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ControlSshAction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accept_env: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ControlSshPrincipal {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node_ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user_login: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub any: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ControlSshAction {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub reject: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub accept: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hold_and_delegate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_duration: Option<u64>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_agent_forwarding: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_local_port_forwarding: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_remote_port_forwarding: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ControlDisplayMessageSeverity {
    High,
    #[default]
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlDialPlan {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<ControlIpCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlClientVersion {
    #[serde(default, skip_serializing_if = "is_false")]
    pub running_latest: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub latest_version: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub urgent_security_update: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub notify: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notify_url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notify_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlIpCandidate {
    #[serde(rename = "IP")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ip: String,
    #[serde(rename = "ACEHost")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ace_host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial_start_delay_sec: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial_timeout_sec: Option<f64>,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlUserProfile {
    pub id: u64,
    #[serde(rename = "LoginName")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub login_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    #[serde(rename = "ProfilePicURL")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile_pic_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlFilterRule {
    #[serde(rename = "SrcIPs")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub src_ips: Vec<String>,
    #[serde(rename = "DstPorts")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dst_ports: Vec<ControlNetPortRange>,
    #[serde(rename = "IPProto")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_proto: Vec<i32>,
    #[serde(rename = "CapGrant")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cap_grant: Vec<ControlCapGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlNetPortRange {
    #[serde(rename = "IP")]
    pub ip: String,
    pub ports: ControlPortRange,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlPortRange {
    pub first: u16,
    pub last: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlCapGrant {
    #[serde(rename = "Dsts")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dsts: Vec<String>,
    #[serde(rename = "CapMap")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cap_map: BTreeMap<String, Option<Vec<Value>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlDnsConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<ControlDnsResolver>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub proxied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ControlDnsResolver {
    #[serde(rename = "Addr")]
    pub addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ControlDerpMap {
    #[serde(rename = "HomeParams")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_params: Option<ControlDerpHomeParams>,
    #[serde(rename = "Regions")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub regions: BTreeMap<u32, ControlDerpRegion>,
    #[serde(rename = "omitDefaultRegions")]
    #[serde(default, skip_serializing_if = "is_false")]
    pub omit_default_regions: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ControlDerpHomeParams {
    #[serde(rename = "RegionScore")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub region_score: BTreeMap<u32, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ControlDerpRegion {
    #[serde(rename = "RegionID")]
    pub region_id: u32,
    #[serde(rename = "RegionCode")]
    pub region_code: String,
    #[serde(rename = "RegionName")]
    pub region_name: String,
    #[serde(rename = "Latitude")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(rename = "Longitude")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(rename = "Avoid")]
    #[serde(default, skip_serializing_if = "is_false")]
    pub avoid: bool,
    #[serde(rename = "NoMeasureNoHome")]
    #[serde(default, skip_serializing_if = "is_false")]
    pub no_measure_no_home: bool,
    #[serde(rename = "Nodes")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<ControlDerpNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ControlDerpNode {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "RegionID")]
    pub region_id: u32,
    #[serde(rename = "HostName")]
    pub host_name: String,
    #[serde(rename = "CertName")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cert_name: String,
    #[serde(rename = "IPv4")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ipv4: String,
    #[serde(rename = "IPv6")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ipv6: String,
    #[serde(rename = "STUNPort")]
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub stun_port: i32,
    #[serde(rename = "STUNOnly")]
    #[serde(default, skip_serializing_if = "is_false")]
    pub stun_only: bool,
    #[serde(rename = "DERPPort")]
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub derp_port: u16,
    #[serde(rename = "InsecureForTests")]
    #[serde(default, skip_serializing_if = "is_false")]
    pub insecure_for_tests: bool,
    #[serde(rename = "STUNTestIP")]
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stun_test_ip: String,
    #[serde(rename = "CanPort80")]
    #[serde(default, skip_serializing_if = "is_false")]
    pub can_port80: bool,
}

pub fn allow_all_packet_filter() -> Vec<ControlFilterRule> {
    vec![ControlFilterRule {
        src_ips: vec!["*".to_string()],
        dst_ports: vec![ControlNetPortRange {
            ip: "*".to_string(),
            ports: ControlPortRange {
                first: 0,
                last: 65535,
            },
        }],
        ip_proto: Vec::new(),
        cap_grant: Vec::new(),
    }]
}

pub fn keep_alive_response() -> MapResponse {
    MapResponse {
        keep_alive: true,
        ..MapResponse::default()
    }
}

pub fn wants_zstd(compress: &str) -> bool {
    compress.eq_ignore_ascii_case("zstd")
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

fn is_zero_u16(value: &u16) -> bool {
    *value == 0
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn map_response_uses_tailcfg_field_names() -> Result<(), Box<dyn Error>> {
        let json = serde_json::to_value(MapResponse {
            node: Some(ControlNode {
                id: 1,
                stable_id: "stable-1".to_string(),
                name: "node.example.com.".to_string(),
                user: 1,
                key: "nodekey:1".to_string(),
                machine: "mkey:1".to_string(),
                allowed_ips: vec!["100.64.0.1/32".to_string()],
                home_derp: 900,
                ..ControlNode::default()
            }),
            derp_map: Some(ControlDerpMap {
                regions: BTreeMap::from([(
                    900,
                    ControlDerpRegion {
                        region_id: 900,
                        region_code: "sha".to_string(),
                        region_name: "Shanghai".to_string(),
                        nodes: vec![ControlDerpNode {
                            name: "900a".to_string(),
                            region_id: 900,
                            host_name: "derp.example.com".to_string(),
                            ..ControlDerpNode::default()
                        }],
                        ..ControlDerpRegion::default()
                    },
                )]),
                ..ControlDerpMap::default()
            }),
            dns_config: Some(ControlDnsConfig {
                resolvers: vec![ControlDnsResolver {
                    addr: "1.1.1.1".to_string(),
                }],
                ..ControlDnsConfig::default()
            }),
            ..MapResponse::default()
        })?;

        assert!(json.get("DERPMap").is_some());
        assert!(json.get("DNSConfig").is_some());
        assert!(json.get("PopBrowserURL").is_none());
        assert!(json.get("CollectServices").is_none());
        assert!(json.get("PeersChanged").is_none());
        assert!(json.get("PeersRemoved").is_none());
        assert!(json.get("PeersChangedPatch").is_none());
        assert!(json.get("PeerSeenChange").is_none());
        assert!(json.get("OnlineChange").is_none());
        assert!(json.get("Health").is_none());
        assert!(json.get("DisplayMessages").is_none());
        assert!(json.get("SSHPolicy").is_none());
        assert!(json.get("ControlDialPlan").is_none());
        assert!(json.get("ClientVersion").is_none());
        assert!(json.get("DefaultAutoUpdate").is_none());

        let node = json
            .get("Node")
            .ok_or_else(|| std::io::Error::other("node should serialize"))?;
        assert!(node.get("StableID").is_some());
        assert!(node.get("AllowedIPs").is_some());
        assert!(node.get("HomeDERP").is_some());
        assert!(node.get("Capabilities").is_none());
        assert!(node.get("CapMap").is_none());
        Ok(())
    }
}
