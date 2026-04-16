use crate::AppResult;
use crate::domain::{AuditEvent, AuthKey, DnsConfig, Node, Route};

pub trait NodeRepository: Send + Sync {
    fn list_nodes(&self) -> AppResult<Vec<Node>>;
    fn save_node(&self, node: &Node) -> AppResult<()>;
}

pub trait AuthKeyRepository: Send + Sync {
    fn save_auth_key(&self, auth_key: &AuthKey) -> AppResult<()>;
}

pub trait RouteRepository: Send + Sync {
    fn list_routes(&self) -> AppResult<Vec<Route>>;
}

pub trait DnsRepository: Send + Sync {
    fn load_dns_config(&self) -> AppResult<DnsConfig>;
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: &AuditEvent) -> AppResult<()>;
}
