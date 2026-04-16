use serde::{Deserialize, Serialize};

use crate::domain::{AclPolicy, DnsConfig, Node, Route};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRegistration {
    pub node: Node,
    pub session_token: String,
    pub map: NodeMap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeHeartbeat {
    pub node: Node,
    pub observed_at_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeMap {
    pub self_node: Node,
    pub peers: Vec<Node>,
    pub policy: AclPolicy,
    pub dns: DnsConfig,
    pub routes: Vec<Route>,
    pub generated_at_unix_secs: u64,
}
