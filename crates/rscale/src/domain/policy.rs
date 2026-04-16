use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::{Node, Principal, Route, validate_route_prefix};
use crate::error::{AppError, AppResult};

const WILDCARD_SELECTOR: &str = "*";
const GROUP_PREFIX: &str = "group:";
const TAG_PREFIX: &str = "tag:";
const AUTOGROUP_SELF: &str = "autogroup:self";
const AUTOGROUP_INTERNET: &str = "autogroup:internet";
const DEFAULT_SSH_CHECK_PERIOD_SECS: u64 = 12 * 60 * 60;
const MIN_SSH_CHECK_PERIOD_SECS: u64 = 60;
const MAX_SSH_CHECK_PERIOD_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AclPolicy {
    pub groups: Vec<PolicySubject>,
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub grants: Vec<GrantRule>,
    #[serde(default, rename = "tagOwners")]
    pub tag_owners: BTreeMap<String, Vec<String>>,
    #[serde(default, rename = "autoApprovers")]
    pub auto_approvers: AutoApproverPolicy,
    #[serde(default, rename = "ssh")]
    pub ssh_rules: Vec<SshPolicyRule>,
}

impl AclPolicy {
    pub fn validate(&self) -> AppResult<()> {
        let groups = group_index(self)?;

        for group in &self.groups {
            let name = normalize_group_name(&group.name)?;
            if group.members.is_empty() {
                return Err(AppError::InvalidRequest(format!(
                    "policy group {name} must contain at least one member",
                )));
            }

            for member in &group.members {
                validate_group_member(member, &groups)?;
            }
        }

        let mut visiting = BTreeSet::new();
        for group in groups.keys() {
            validate_group_cycles(group, &groups, &mut visiting, &mut BTreeSet::new())?;
        }

        for rule in &self.rules {
            if rule.action != "accept" {
                return Err(AppError::InvalidRequest(format!(
                    "unsupported policy action: {}",
                    rule.action
                )));
            }

            if rule.sources.is_empty() {
                return Err(AppError::InvalidRequest(
                    "policy rule must contain at least one source".to_string(),
                ));
            }

            if rule.destinations.is_empty() {
                return Err(AppError::InvalidRequest(
                    "policy rule must contain at least one destination".to_string(),
                ));
            }

            for source in &rule.sources {
                validate_source_selector(source, &groups)?;
            }

            for destination in &rule.destinations {
                validate_destination_selector(destination, &groups)?;
            }
        }

        for grant in &self.grants {
            validate_grant_rule(grant, &groups)?;
        }

        validate_tag_owners(&self.tag_owners, &groups)?;
        validate_auto_approvers(&self.auto_approvers, &groups)?;

        for rule in &self.ssh_rules {
            validate_ssh_rule(rule, &groups)?;
        }

        Ok(())
    }

    pub fn is_default_allow(&self) -> bool {
        self.groups.is_empty() && self.rules.is_empty() && self.grants.is_empty()
    }

    pub fn auto_approves_route(
        &self,
        node: &Node,
        principal: Option<&Principal>,
        route: &Route,
    ) -> AppResult<bool> {
        self.validate()?;

        let groups = group_index(self)?;

        if is_exit_route(&route.prefix) {
            return self
                .auto_approvers
                .exit_node
                .iter()
                .try_fold(false, |matched, selector| {
                    if matched {
                        return Ok(true);
                    }

                    auto_approver_matches_node(selector, node, principal, &groups)
                });
        }

        for (approved_prefix, approvers) in &self.auto_approvers.routes {
            if !route_is_within_auto_approver_prefix(approved_prefix, &route.prefix)? {
                continue;
            }

            if approvers.iter().try_fold(false, |matched, selector| {
                if matched {
                    return Ok(true);
                }

                auto_approver_matches_node(selector, node, principal, &groups)
            })? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn approved_request_tags(
        &self,
        node: &Node,
        principal: Option<&Principal>,
        request_tags: &[String],
    ) -> AppResult<Vec<String>> {
        self.validate()?;

        let request_tags = normalize_acl_tags(request_tags)?;
        if request_tags.is_empty() {
            return Ok(Vec::new());
        }

        let groups = group_index(self)?;
        let tag_owners = normalized_tag_owner_index(&self.tag_owners)?;
        resolve_approved_request_tags(node, principal, &request_tags, &groups, &tag_owners)
    }

    pub fn evaluate_for_node(
        &self,
        subject: &Node,
        nodes: &[Node],
        routes: &[Route],
    ) -> AppResult<NodePolicyView> {
        self.validate()?;

        let groups = group_index(self)?;
        let routes_by_node = routes_by_node(routes);

        if self.is_default_allow() {
            let visible_peer_ids = nodes
                .iter()
                .filter(|node| node.id != subject.id)
                .map(|node| node.id)
                .collect::<BTreeSet<_>>();
            let visible_route_ids = routes.iter().map(|route| route.id).collect();

            return Ok(NodePolicyView {
                packet_rules: vec![CompiledAclRule {
                    src_ips: vec![WILDCARD_SELECTOR.to_string()],
                    destinations: vec![CompiledAclDestination {
                        network: WILDCARD_SELECTOR.to_string(),
                        ports: vec![PolicyPortRange {
                            first: 0,
                            last: u16::MAX,
                        }],
                    }],
                }],
                grant_ip_rules: Vec::new(),
                cap_grant_rules: Vec::new(),
                visible_peer_ids,
                visible_route_ids,
            });
        }

        let packet_rules = self
            .rules
            .iter()
            .map(|rule| compile_rule_for_subject(rule, subject, nodes, &routes_by_node, &groups))
            .collect::<AppResult<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();

        let cap_grant_rules = self
            .grants
            .iter()
            .map(|grant| {
                compile_app_grant_rules_for_subject(grant, subject, nodes, &routes_by_node, &groups)
            })
            .collect::<AppResult<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();

        let grant_ip_rules = self
            .grants
            .iter()
            .map(|grant| {
                compile_ip_grant_rules_for_subject(grant, subject, nodes, &routes_by_node, &groups)
            })
            .collect::<AppResult<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();

        let mut visible_peer_ids = BTreeSet::new();
        for peer in nodes.iter().filter(|node| node.id != subject.id) {
            let mut visible = false;
            for rule in &self.rules {
                if rule_connects_nodes(rule, subject, peer, subject, &routes_by_node, &groups)?
                    || rule_connects_nodes(rule, peer, subject, subject, &routes_by_node, &groups)?
                {
                    visible = true;
                    break;
                }
            }

            if !visible {
                for grant in &self.grants {
                    if grant_connects_nodes(
                        grant,
                        subject,
                        peer,
                        subject,
                        &routes_by_node,
                        &groups,
                    )? || grant_connects_nodes(
                        grant,
                        peer,
                        subject,
                        subject,
                        &routes_by_node,
                        &groups,
                    )? {
                        visible = true;
                        break;
                    }
                }
            }

            if visible {
                visible_peer_ids.insert(peer.id);
            }
        }

        let mut visible_route_ids = BTreeSet::new();
        for route in routes {
            let Some(owner) = nodes.iter().find(|node| node.id == route.node_id) else {
                continue;
            };

            let mut visible = false;
            for rule in &self.rules {
                if rule_grants_route(
                    rule,
                    subject,
                    owner,
                    route,
                    subject,
                    &routes_by_node,
                    &groups,
                )? {
                    visible = true;
                    break;
                }
            }

            if !visible {
                for grant in &self.grants {
                    if grant_grants_route(
                        grant,
                        subject,
                        owner,
                        route,
                        subject,
                        &routes_by_node,
                        &groups,
                    )? {
                        visible = true;
                        break;
                    }
                }
            }

            if visible {
                visible_route_ids.insert(route.id);
            }
        }

        Ok(NodePolicyView {
            packet_rules,
            grant_ip_rules,
            cap_grant_rules,
            visible_peer_ids,
            visible_route_ids,
        })
    }

    pub fn evaluate_ssh_for_node(
        &self,
        subject: &Node,
        nodes: &[Node],
        routes: &[Route],
    ) -> AppResult<NodeSshPolicyView> {
        self.validate()?;

        let groups = group_index(self)?;
        let routes_by_node = routes_by_node(routes);
        let mut compiled_rules = Vec::new();

        for rule in &self.ssh_rules {
            if !ssh_rule_targets_node(rule, subject, &routes_by_node, &groups)? {
                continue;
            }

            let principals = compile_ssh_principals(&rule.sources, nodes, &groups)?;
            if principals.is_empty() {
                continue;
            }

            compiled_rules.push(CompiledSshRule {
                principals,
                ssh_users: rule.ssh_users.clone(),
                action: CompiledSshAction {
                    message: rule.message.clone(),
                    reject: matches!(rule.action, SshPolicyAction::Reject),
                    accept: matches!(rule.action, SshPolicyAction::Accept),
                    check: matches!(rule.action, SshPolicyAction::Check),
                    check_period_secs: matches!(rule.action, SshPolicyAction::Check).then_some(
                        rule.check_period_secs
                            .unwrap_or(DEFAULT_SSH_CHECK_PERIOD_SECS),
                    ),
                    session_duration_secs: rule.session_duration_secs,
                    allow_agent_forwarding: rule.allow_agent_forwarding,
                    allow_local_port_forwarding: rule.allow_local_port_forwarding,
                    allow_remote_port_forwarding: rule.allow_remote_port_forwarding,
                },
                accept_env: rule.accept_env.clone(),
            });
        }

        compiled_rules.sort_by_key(|rule| {
            if rule.action.check {
                0_u8
            } else if rule.action.reject {
                1
            } else {
                2
            }
        });

        Ok(NodeSshPolicyView {
            rules: compiled_rules,
        })
    }

    pub fn ssh_check_period_for_pair(
        &self,
        source: &Node,
        destination: &Node,
        nodes: &[Node],
        routes: &[Route],
    ) -> AppResult<Option<u64>> {
        Ok(self
            .ssh_check_action_for_pair(source, destination, nodes, routes)?
            .and_then(|action| action.check_period_secs))
    }

    pub fn ssh_check_action_for_pair(
        &self,
        source: &Node,
        destination: &Node,
        nodes: &[Node],
        routes: &[Route],
    ) -> AppResult<Option<CompiledSshAction>> {
        let ssh_view = self.evaluate_ssh_for_node(destination, nodes, routes)?;

        for rule in ssh_view.rules {
            if !rule.action.check {
                continue;
            }

            if rule
                .principals
                .iter()
                .any(|principal| compiled_ssh_principal_matches_node(principal, source))
            {
                return Ok(Some(rule.action));
            }
        }

        Ok(None)
    }

    pub fn ssh_check_action_for_connection(
        &self,
        source: &Node,
        destination: &Node,
        requested_user: &str,
        expected_local_user: Option<&str>,
        nodes: &[Node],
        routes: &[Route],
    ) -> AppResult<Option<(CompiledSshAction, String)>> {
        let requested_user = requested_user.trim();
        if requested_user.is_empty() {
            return Ok(None);
        }
        let expected_local_user = expected_local_user
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let ssh_view = self.evaluate_ssh_for_node(destination, nodes, routes)?;

        for rule in ssh_view.rules {
            if !rule.action.check {
                continue;
            }

            if !rule
                .principals
                .iter()
                .any(|principal| compiled_ssh_principal_matches_node(principal, source))
            {
                continue;
            }

            let Some(local_user) = compiled_ssh_local_user(&rule.ssh_users, requested_user) else {
                continue;
            };
            if expected_local_user.is_some_and(|expected| expected != local_user) {
                continue;
            }

            return Ok(Some((rule.action, local_user)));
        }

        Ok(None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySubject {
    pub name: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AutoApproverPolicy {
    #[serde(default)]
    pub routes: BTreeMap<String, Vec<String>>,
    #[serde(default, rename = "exitNode")]
    pub exit_node: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub action: String,
    pub sources: Vec<String>,
    pub destinations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GrantRule {
    #[serde(default, alias = "src")]
    pub sources: Vec<String>,
    #[serde(default, alias = "dst")]
    pub destinations: Vec<String>,
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub via: Vec<String>,
    #[serde(default)]
    pub app: BTreeMap<String, Vec<Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshPolicyRule {
    pub action: SshPolicyAction,
    #[serde(default, alias = "src")]
    pub sources: Vec<String>,
    #[serde(default, alias = "dst")]
    pub destinations: Vec<String>,
    #[serde(default, alias = "sshUsers")]
    pub ssh_users: BTreeMap<String, String>,
    #[serde(default)]
    pub accept_env: Vec<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default = "default_true")]
    pub allow_agent_forwarding: bool,
    #[serde(default = "default_true")]
    pub allow_local_port_forwarding: bool,
    #[serde(default = "default_true")]
    pub allow_remote_port_forwarding: bool,
    #[serde(default)]
    pub session_duration_secs: Option<u64>,
    #[serde(default)]
    pub check_period_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SshPolicyAction {
    Accept,
    Check,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePolicyView {
    pub packet_rules: Vec<CompiledAclRule>,
    pub grant_ip_rules: Vec<CompiledGrantIpRule>,
    pub cap_grant_rules: Vec<CompiledCapGrantRule>,
    pub visible_peer_ids: BTreeSet<u64>,
    pub visible_route_ids: BTreeSet<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSshPolicyView {
    pub rules: Vec<CompiledSshRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledAclRule {
    pub src_ips: Vec<String>,
    pub destinations: Vec<CompiledAclDestination>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledAclDestination {
    pub network: String,
    pub ports: Vec<PolicyPortRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledGrantIpRule {
    pub src_ips: Vec<String>,
    pub destinations: Vec<CompiledAclDestination>,
    pub ip_protocols: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledCapGrantRule {
    pub src_ips: Vec<String>,
    pub grants: Vec<CompiledCapGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledCapGrant {
    pub destinations: Vec<String>,
    pub cap_map: BTreeMap<String, Option<Vec<Value>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSshRule {
    pub principals: Vec<CompiledSshPrincipal>,
    pub ssh_users: BTreeMap<String, String>,
    pub action: CompiledSshAction,
    pub accept_env: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledSshAction {
    pub message: Option<String>,
    pub reject: bool,
    pub accept: bool,
    pub check: bool,
    pub check_period_secs: Option<u64>,
    pub session_duration_secs: Option<u64>,
    pub allow_agent_forwarding: bool,
    pub allow_local_port_forwarding: bool,
    pub allow_remote_port_forwarding: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompiledSshPrincipal {
    Any,
    NodeIp(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyPortRange {
    pub first: u16,
    pub last: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GrantIpSpec {
    ports: Vec<PolicyPortRange>,
    ip_protocols: Vec<i32>,
}

pub fn normalize_acl_tags(tags: &[String]) -> AppResult<Vec<String>> {
    let mut normalized = BTreeSet::new();
    for tag in tags {
        normalized.insert(normalize_tag_name(tag)?);
    }

    Ok(normalized.into_iter().collect())
}

fn group_index(policy: &AclPolicy) -> AppResult<BTreeMap<String, Vec<String>>> {
    let mut groups = BTreeMap::new();
    for group in &policy.groups {
        let name = normalize_group_name(&group.name)?;
        if groups.insert(name.clone(), group.members.clone()).is_some() {
            return Err(AppError::InvalidRequest(format!(
                "policy group {name} is defined more than once",
            )));
        }
    }

    Ok(groups)
}

fn normalize_group_name(value: &str) -> AppResult<String> {
    let name = value.trim().trim_start_matches(GROUP_PREFIX).trim();
    if name.is_empty() {
        return Err(AppError::InvalidRequest(
            "policy group name must not be empty".to_string(),
        ));
    }

    Ok(name.to_string())
}

fn normalize_tag_name(value: &str) -> AppResult<String> {
    let selector = value.trim();
    if !selector.starts_with(TAG_PREFIX) {
        return Err(AppError::InvalidRequest(format!(
            "tag selector must start with {TAG_PREFIX}: {selector}",
        )));
    }

    let name = selector[TAG_PREFIX.len()..].trim();
    if name.is_empty() {
        return Err(AppError::InvalidRequest(
            "tag selector must not be empty".to_string(),
        ));
    }

    if name.contains(char::is_whitespace) {
        return Err(AppError::InvalidRequest(format!(
            "tag selector must not contain whitespace: {selector}",
        )));
    }

    Ok(format!("{TAG_PREFIX}{name}"))
}

fn validate_group_member(value: &str, groups: &BTreeMap<String, Vec<String>>) -> AppResult<()> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::InvalidRequest(
            "policy group members must not be empty".to_string(),
        ));
    }

    if let Some(name) = value.strip_prefix(GROUP_PREFIX)
        && !groups.contains_key(name)
    {
        return Err(AppError::InvalidRequest(format!(
            "policy group references undefined group {name}",
        )));
    }

    if value == AUTOGROUP_SELF {
        return Err(AppError::InvalidRequest(
            "autogroup:self is not supported inside policy groups".to_string(),
        ));
    }

    Ok(())
}

fn validate_group_cycles(
    group: &str,
    groups: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> AppResult<()> {
    if visited.contains(group) {
        return Ok(());
    }

    if !visiting.insert(group.to_string()) {
        return Err(AppError::InvalidRequest(format!(
            "policy group graph contains a cycle involving {group}",
        )));
    }

    if let Some(members) = groups.get(group) {
        for member in members {
            if let Some(child) = member.strip_prefix(GROUP_PREFIX) {
                validate_group_cycles(child, groups, visiting, visited)?;
            }
        }
    }

    visiting.remove(group);
    visited.insert(group.to_string());
    Ok(())
}

fn validate_source_selector(value: &str, groups: &BTreeMap<String, Vec<String>>) -> AppResult<()> {
    let selector = value.trim();
    if selector.is_empty() {
        return Err(AppError::InvalidRequest(
            "policy rule contains an empty source entry".to_string(),
        ));
    }

    if selector == AUTOGROUP_SELF {
        return Err(AppError::InvalidRequest(
            "autogroup:self is only supported in policy destinations".to_string(),
        ));
    }

    if selector == AUTOGROUP_INTERNET {
        return Err(AppError::InvalidRequest(
            "autogroup:internet is only supported in policy destinations".to_string(),
        ));
    }

    if let Some(name) = selector.strip_prefix(GROUP_PREFIX)
        && !groups.contains_key(name)
    {
        return Err(AppError::InvalidRequest(format!(
            "policy rule references undefined group {name}",
        )));
    }

    if selector.starts_with('[') && selector.ends_with(']') {
        return Err(AppError::InvalidRequest(
            "bracketed IPv6 selectors are only valid in destinations with ports".to_string(),
        ));
    }

    Ok(())
}

fn validate_destination_selector(
    value: &str,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<()> {
    let (selector, ports) = parse_destination_expression(value)?;
    if selector.is_empty() {
        return Err(AppError::InvalidRequest(
            "policy rule contains an empty destination selector".to_string(),
        ));
    }

    if let Some(name) = selector.strip_prefix(GROUP_PREFIX)
        && !groups.contains_key(name)
    {
        return Err(AppError::InvalidRequest(format!(
            "policy rule references undefined group {name}",
        )));
    }

    if ports.is_empty() {
        return Err(AppError::InvalidRequest(
            "policy destination must include at least one port range".to_string(),
        ));
    }

    Ok(())
}

fn validate_ssh_rule(
    rule: &SshPolicyRule,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<()> {
    if rule.sources.is_empty() {
        return Err(AppError::InvalidRequest(
            "ssh policy rule must contain at least one source".to_string(),
        ));
    }

    if rule.destinations.is_empty() {
        return Err(AppError::InvalidRequest(
            "ssh policy rule must contain at least one destination".to_string(),
        ));
    }

    for source in &rule.sources {
        validate_source_selector(source, groups)?;
    }

    for destination in &rule.destinations {
        let selector = destination.trim();
        if selector.is_empty() {
            return Err(AppError::InvalidRequest(
                "ssh policy rule contains an empty destination entry".to_string(),
            ));
        }

        if selector != AUTOGROUP_SELF && selector != AUTOGROUP_INTERNET {
            validate_source_selector(selector, groups)?;
        }
        if is_raw_network(selector) && is_exit_route(selector) {
            return Err(AppError::InvalidRequest(
                "grant destinations must use autogroup:internet instead of raw default routes"
                    .to_string(),
            ));
        }
    }

    if matches!(
        rule.action,
        SshPolicyAction::Accept | SshPolicyAction::Check
    ) {
        if rule.ssh_users.is_empty() {
            return Err(AppError::InvalidRequest(
                "ssh accept/check rule must define at least one ssh user mapping".to_string(),
            ));
        }

        if !rule
            .ssh_users
            .values()
            .any(|value| !value.trim().is_empty())
        {
            return Err(AppError::InvalidRequest(
                "ssh accept/check rule must define at least one non-empty ssh user mapping"
                    .to_string(),
            ));
        }
    }

    for (requested_user, local_user) in &rule.ssh_users {
        if requested_user.trim().is_empty() {
            return Err(AppError::InvalidRequest(
                "ssh user mappings must not contain an empty user key".to_string(),
            ));
        }

        if local_user != "=" && local_user.trim() != *local_user {
            return Err(AppError::InvalidRequest(
                "ssh user mapping values must not contain surrounding whitespace".to_string(),
            ));
        }
    }

    if let Some(message) = rule.message.as_deref()
        && message.trim().is_empty()
    {
        return Err(AppError::InvalidRequest(
            "ssh policy rule message must not be empty when configured".to_string(),
        ));
    }

    if rule.session_duration_secs == Some(0) {
        return Err(AppError::InvalidRequest(
            "ssh policy rule session_duration_secs must be greater than zero when configured"
                .to_string(),
        ));
    }

    if let Some(check_period_secs) = rule.check_period_secs {
        if !matches!(rule.action, SshPolicyAction::Check) {
            return Err(AppError::InvalidRequest(
                "ssh policy rule check_period_secs is only valid for action=check".to_string(),
            ));
        }

        if !(MIN_SSH_CHECK_PERIOD_SECS..=MAX_SSH_CHECK_PERIOD_SECS).contains(&check_period_secs) {
            return Err(AppError::InvalidRequest(format!(
                "ssh policy rule check_period_secs must be between {MIN_SSH_CHECK_PERIOD_SECS} and {MAX_SSH_CHECK_PERIOD_SECS}",
            )));
        }
    }

    for pattern in &rule.accept_env {
        if pattern.trim().is_empty() {
            return Err(AppError::InvalidRequest(
                "ssh accept_env entries must not be empty".to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_grant_rule(grant: &GrantRule, groups: &BTreeMap<String, Vec<String>>) -> AppResult<()> {
    if grant.sources.is_empty() {
        return Err(AppError::InvalidRequest(
            "grant rule must contain at least one source".to_string(),
        ));
    }

    if grant.destinations.is_empty() {
        return Err(AppError::InvalidRequest(
            "grant rule must contain at least one destination".to_string(),
        ));
    }

    if grant.ip.is_empty() && grant.app.is_empty() {
        return Err(AppError::InvalidRequest(
            "grant rule must define at least one ip or app capability".to_string(),
        ));
    }

    for source in &grant.sources {
        validate_source_selector(source, groups)?;
    }

    for destination in &grant.destinations {
        let selector = destination.trim();
        if selector.is_empty() {
            return Err(AppError::InvalidRequest(
                "grant rule contains an empty destination entry".to_string(),
            ));
        }

        if selector != AUTOGROUP_SELF && selector != AUTOGROUP_INTERNET {
            validate_source_selector(selector, groups)?;
        }
    }

    for internet_protocol in &grant.ip {
        parse_grant_ip_spec(internet_protocol)?;
    }

    for capability in grant.app.keys() {
        validate_grant_capability_name(capability)?;
    }

    if !grant.app.is_empty()
        && grant
            .destinations
            .iter()
            .any(|destination| destination.trim() == AUTOGROUP_INTERNET)
    {
        return Err(AppError::InvalidRequest(
            "grant app capabilities cannot target autogroup:internet".to_string(),
        ));
    }

    for via in &grant.via {
        let via = via.trim();
        if via.is_empty() {
            return Err(AppError::InvalidRequest(
                "grant via selectors must not be empty".to_string(),
            ));
        }
        if !via.starts_with(TAG_PREFIX) {
            return Err(AppError::InvalidRequest(
                "grant via selectors must be tag selectors".to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_tag_owners(
    tag_owners: &BTreeMap<String, Vec<String>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<()> {
    let tag_owners = normalized_tag_owner_index(tag_owners)?;

    for (tag, owners) in &tag_owners {
        for owner in owners {
            validate_tag_owner_selector(tag, owner, groups, &tag_owners)?;
        }
    }

    let mut visited = BTreeSet::new();
    for tag in tag_owners.keys() {
        validate_tag_owner_cycles(tag, &tag_owners, &mut BTreeSet::new(), &mut visited)?;
    }

    Ok(())
}

fn normalized_tag_owner_index(
    tag_owners: &BTreeMap<String, Vec<String>>,
) -> AppResult<BTreeMap<String, Vec<String>>> {
    let mut normalized = BTreeMap::new();
    for (tag, owners) in tag_owners {
        normalized.insert(normalize_tag_name(tag)?, owners.clone());
    }

    Ok(normalized)
}

fn validate_tag_owner_selector(
    owner_tag: &str,
    selector: &str,
    groups: &BTreeMap<String, Vec<String>>,
    tag_owners: &BTreeMap<String, Vec<String>>,
) -> AppResult<()> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err(AppError::InvalidRequest(format!(
            "tagOwners entry for {owner_tag} must not contain empty selectors",
        )));
    }

    if selector.starts_with(TAG_PREFIX) {
        let child = normalize_tag_name(selector)?;
        if !tag_owners.contains_key(&child) {
            return Err(AppError::InvalidRequest(format!(
                "tag \"{owner_tag}\" references undefined tag \"{child}\"",
            )));
        }
        return Ok(());
    }

    if let Some(group) = selector.strip_prefix(GROUP_PREFIX) {
        if !groups.contains_key(group) {
            return Err(AppError::InvalidRequest(format!(
                "tagOwners for {owner_tag} references undefined group {group}",
            )));
        }
        return Ok(());
    }

    if is_username_selector(selector) {
        return Ok(());
    }

    Err(AppError::InvalidRequest(format!(
        "unsupported tagOwners selector {selector}",
    )))
}

fn validate_tag_owner_cycles(
    tag: &str,
    tag_owners: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> AppResult<()> {
    if visited.contains(tag) {
        return Ok(());
    }

    if !visiting.insert(tag.to_string()) {
        return Err(AppError::InvalidRequest(format!(
            "tag owner graph contains a cycle involving {tag}",
        )));
    }

    if let Some(owners) = tag_owners.get(tag) {
        for owner in owners {
            if owner.starts_with(TAG_PREFIX) {
                validate_tag_owner_cycles(
                    &normalize_tag_name(owner)?,
                    tag_owners,
                    visiting,
                    visited,
                )?;
            }
        }
    }

    visiting.remove(tag);
    visited.insert(tag.to_string());
    Ok(())
}

fn validate_auto_approvers(
    auto_approvers: &AutoApproverPolicy,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<()> {
    for prefix in auto_approvers.routes.keys() {
        validate_route_prefix(prefix)?;
    }

    for approvers in auto_approvers.routes.values() {
        validate_auto_approver_selectors(approvers, groups)?;
    }

    validate_auto_approver_selectors(&auto_approvers.exit_node, groups)?;
    Ok(())
}

fn validate_auto_approver_selectors(
    selectors: &[String],
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<()> {
    for selector in selectors {
        validate_auto_approver_selector(selector, groups)?;
    }

    Ok(())
}

fn validate_auto_approver_selector(
    selector: &str,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<()> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err(AppError::InvalidRequest(
            "auto approver selectors must not be empty".to_string(),
        ));
    }

    if selector.starts_with(TAG_PREFIX) {
        return Ok(());
    }

    if let Some(name) = selector.strip_prefix(GROUP_PREFIX) {
        if !groups.contains_key(name) {
            return Err(AppError::InvalidRequest(format!(
                "auto approver references undefined group {name}",
            )));
        }
        return Ok(());
    }

    if is_username_selector(selector) {
        return Ok(());
    }

    Err(AppError::InvalidRequest(format!(
        "unsupported auto approver selector {selector}",
    )))
}

fn resolve_approved_request_tags(
    node: &Node,
    principal: Option<&Principal>,
    request_tags: &[String],
    groups: &BTreeMap<String, Vec<String>>,
    tag_owners: &BTreeMap<String, Vec<String>>,
) -> AppResult<Vec<String>> {
    let requested = request_tags.iter().cloned().collect::<BTreeSet<_>>();
    let mut effective_tags = node
        .tags
        .iter()
        .filter(|tag| tag.starts_with(TAG_PREFIX))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut approved = BTreeSet::new();

    loop {
        let mut changed = false;

        for tag in &requested {
            if approved.contains(tag) {
                continue;
            }

            if request_tag_is_permitted(tag, principal, &effective_tags, groups, tag_owners)? {
                approved.insert(tag.clone());
                effective_tags.insert(tag.clone());
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }

    Ok(approved.into_iter().collect())
}

fn request_tag_is_permitted(
    tag: &str,
    principal: Option<&Principal>,
    effective_tags: &BTreeSet<String>,
    groups: &BTreeMap<String, Vec<String>>,
    tag_owners: &BTreeMap<String, Vec<String>>,
) -> AppResult<bool> {
    let Some(owners) = tag_owners.get(tag) else {
        return Ok(false);
    };

    for owner in owners {
        if tag_owner_selector_matches(owner, principal, effective_tags, groups, tag_owners)? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn tag_owner_selector_matches(
    selector: &str,
    principal: Option<&Principal>,
    effective_tags: &BTreeSet<String>,
    groups: &BTreeMap<String, Vec<String>>,
    tag_owners: &BTreeMap<String, Vec<String>>,
) -> AppResult<bool> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Ok(false);
    }

    if selector.starts_with(TAG_PREFIX) {
        return Ok(effective_tags.contains(&normalize_tag_name(selector)?));
    }

    if let Some(group) = selector.strip_prefix(GROUP_PREFIX) {
        return group_matches_tag_owner(
            group,
            principal,
            effective_tags,
            groups,
            tag_owners,
            &mut BTreeSet::new(),
        );
    }

    Ok(principal.is_some_and(|principal| principal_username_matches(selector, principal)))
}

fn group_matches_tag_owner(
    group: &str,
    principal: Option<&Principal>,
    effective_tags: &BTreeSet<String>,
    groups: &BTreeMap<String, Vec<String>>,
    tag_owners: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
) -> AppResult<bool> {
    if !visiting.insert(group.to_string()) {
        return Err(AppError::InvalidRequest(format!(
            "policy group graph contains a cycle involving {group}",
        )));
    }

    let mut matched = false;
    if let Some(members) = groups.get(group) {
        for member in members {
            let member_matches = if let Some(child) = member.strip_prefix(GROUP_PREFIX) {
                group_matches_tag_owner(
                    child,
                    principal,
                    effective_tags,
                    groups,
                    tag_owners,
                    visiting,
                )?
            } else {
                tag_owner_selector_matches(member, principal, effective_tags, groups, tag_owners)?
            };

            if member_matches {
                matched = true;
                break;
            }
        }
    }

    visiting.remove(group);
    Ok(matched)
}

fn validate_grant_capability_name(value: &str) -> AppResult<()> {
    let capability = value.trim();
    if capability.is_empty() {
        return Err(AppError::InvalidRequest(
            "grant app capability names must not be empty".to_string(),
        ));
    }
    if capability.contains(char::is_whitespace) || !capability.contains('/') {
        return Err(AppError::InvalidRequest(format!(
            "invalid grant app capability name {capability}",
        )));
    }

    if capability.starts_with("tailscale.com/")
        && !is_allowed_tailscale_grant_capability(capability)
    {
        return Err(AppError::InvalidRequest(format!(
            "unsupported built-in grant capability {capability}",
        )));
    }

    Ok(())
}

fn is_allowed_tailscale_grant_capability(value: &str) -> bool {
    matches!(
        value,
        "tailscale.com/cap/drive"
            | "tailscale.com/cap/relay"
            | "tailscale.com/cap/webui"
            | "tailscale.com/cap/kubernetes"
            | "tailscale.com/cap/tsidp"
            | "https://tailscale.com/cap/file-sharing-target"
            | "https://tailscale.com/cap/file-send"
            | "https://tailscale.com/cap/debug-peer"
            | "https://tailscale.com/cap/wake-on-lan"
    )
}

fn parse_destination_expression(value: &str) -> AppResult<(String, Vec<PolicyPortRange>)> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::InvalidRequest(
            "policy rule contains an empty destination entry".to_string(),
        ));
    }

    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(|| {
            AppError::InvalidRequest(
                "IPv6 destinations with ports must use a closing bracket".to_string(),
            )
        })?;
        let selector = rest[..end].to_string();
        let port_spec = &rest[end + 1..];
        if port_spec.is_empty() {
            return Ok((selector, vec![full_port_range()]));
        }
        let port_spec = port_spec.strip_prefix(':').ok_or_else(|| {
            AppError::InvalidRequest("IPv6 destinations must use the form [addr]:port".to_string())
        })?;
        return Ok((selector, parse_port_spec(port_spec)?));
    }

    if is_raw_network(value) {
        return Ok((value.to_string(), vec![full_port_range()]));
    }

    if let Some((selector, port_spec)) = value.rsplit_once(':')
        && is_valid_port_spec(port_spec)
    {
        return Ok((selector.to_string(), parse_port_spec(port_spec)?));
    }

    Ok((value.to_string(), vec![full_port_range()]))
}

fn default_true() -> bool {
    true
}

fn parse_port_spec(value: &str) -> AppResult<Vec<PolicyPortRange>> {
    if value == "*" {
        return Ok(vec![full_port_range()]);
    }

    let mut ranges = BTreeSet::new();
    for raw_part in value.split(',') {
        let part = raw_part.trim();
        if part.is_empty() {
            return Err(AppError::InvalidRequest(format!(
                "invalid empty port entry in destination port spec {value}",
            )));
        }

        let range = if let Some((first, last)) = part.split_once('-') {
            let first = parse_port(first)?;
            let last = parse_port(last)?;
            if first > last {
                return Err(AppError::InvalidRequest(format!(
                    "invalid descending port range {part}",
                )));
            }
            PolicyPortRange { first, last }
        } else {
            let port = parse_port(part)?;
            PolicyPortRange {
                first: port,
                last: port,
            }
        };

        ranges.insert(range);
    }

    Ok(ranges.into_iter().collect())
}

fn parse_port(value: &str) -> AppResult<u16> {
    value
        .parse::<u16>()
        .map_err(|err| AppError::InvalidRequest(format!("invalid port value {value}: {err}")))
}

fn is_valid_port_spec(value: &str) -> bool {
    if value == "*" {
        return true;
    }

    !value.is_empty()
        && value.split(',').all(|part| {
            let part = part.trim();
            if part.is_empty() {
                return false;
            }
            if let Some((first, last)) = part.split_once('-') {
                return first.parse::<u16>().is_ok() && last.parse::<u16>().is_ok();
            }
            part.parse::<u16>().is_ok()
        })
}

fn full_port_range() -> PolicyPortRange {
    PolicyPortRange {
        first: 0,
        last: u16::MAX,
    }
}

fn parse_grant_ip_spec(value: &str) -> AppResult<GrantIpSpec> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::InvalidRequest(
            "grant ip entries must not be empty".to_string(),
        ));
    }

    let (protocol, port_spec) = match value.split_once(':') {
        Some((protocol, port_spec)) => {
            if port_spec.contains(':') {
                return Err(AppError::InvalidRequest(format!(
                    "invalid grant ip entry {value}: too many ':' separators",
                )));
            }
            (Some(protocol.trim()), port_spec.trim())
        }
        None => (None, value),
    };

    let ip_protocols = protocol
        .map(parse_grant_ip_protocol)
        .transpose()?
        .unwrap_or_default();
    let ports = parse_port_spec(port_spec)?;

    if !grant_ip_protocols_support_specific_ports(&ip_protocols)
        && ports.iter().any(|range| *range != full_port_range())
    {
        return Err(AppError::InvalidRequest(format!(
            "grant ip entry {value} uses a protocol that only supports '*' ports",
        )));
    }

    Ok(GrantIpSpec {
        ports,
        ip_protocols,
    })
}

fn parse_grant_ip_protocol(value: &str) -> AppResult<Vec<i32>> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(Vec::new());
    }

    let protocol = match normalized.as_str() {
        "tcp" => 6,
        "udp" => 17,
        "sctp" => 132,
        "icmp" => 1,
        "ipv6-icmp" | "icmpv6" => 58,
        "gre" => 47,
        "*" => {
            return Err(AppError::InvalidRequest(
                "grant ip protocol '*' is not supported; omit the protocol instead".to_string(),
            ));
        }
        _ => normalized.parse::<i32>().map_err(|err| {
            AppError::InvalidRequest(format!("invalid grant ip protocol {value}: {err}",))
        })?,
    };

    if !(0..=255).contains(&protocol) {
        return Err(AppError::InvalidRequest(format!(
            "grant ip protocol {value} must be between 0 and 255",
        )));
    }

    Ok(vec![protocol])
}

fn grant_ip_protocols_support_specific_ports(protocols: &[i32]) -> bool {
    protocols.is_empty()
        || protocols
            .iter()
            .all(|protocol| matches!(protocol, 6 | 17 | 132))
}

fn auto_approver_matches_node(
    selector: &str,
    node: &Node,
    principal: Option<&Principal>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<bool> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Ok(false);
    }

    if selector.starts_with(TAG_PREFIX) {
        return Ok(node.tags.iter().any(|tag| tag == selector));
    }

    if let Some(group) = selector.strip_prefix(GROUP_PREFIX) {
        return group_matches_auto_approver(group, node, principal, groups, &mut BTreeSet::new());
    }

    if node_is_tagged_identity(node) {
        return Ok(false);
    }

    Ok(principal.is_some_and(|principal| principal_username_matches(selector, principal)))
}

fn group_matches_auto_approver(
    group: &str,
    node: &Node,
    principal: Option<&Principal>,
    groups: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
) -> AppResult<bool> {
    if !visiting.insert(group.to_string()) {
        return Err(AppError::InvalidRequest(format!(
            "policy group graph contains a cycle involving {group}",
        )));
    }

    let mut matched = false;
    if let Some(members) = groups.get(group) {
        for member in members {
            let member_matches = if let Some(child) = member.strip_prefix(GROUP_PREFIX) {
                group_matches_auto_approver(child, node, principal, groups, visiting)?
            } else {
                auto_approver_matches_node(member, node, principal, groups)?
            };

            if member_matches {
                matched = true;
                break;
            }
        }
    }

    visiting.remove(group);
    Ok(matched)
}

fn node_is_tagged_identity(node: &Node) -> bool {
    node.tags.iter().any(|tag| tag.starts_with(TAG_PREFIX))
}

fn is_username_selector(selector: &str) -> bool {
    selector.contains('@')
        && !selector.starts_with(GROUP_PREFIX)
        && !selector.starts_with(TAG_PREFIX)
        && !selector.contains(char::is_whitespace)
}

fn principal_username_matches(selector: &str, principal: &Principal) -> bool {
    let selector = selector.trim().to_ascii_lowercase();
    if selector.is_empty() {
        return false;
    }

    let mut candidates = BTreeSet::new();
    candidates.insert(principal.login_name.trim().to_ascii_lowercase());
    if let Some(email) = principal.email.as_deref() {
        candidates.insert(email.trim().to_ascii_lowercase());
    }

    if selector.ends_with('@') {
        let prefix = selector.trim_end_matches('@');
        candidates.iter().any(|candidate| {
            candidate == &selector
                || candidate
                    .strip_suffix('@')
                    .is_some_and(|trimmed| trimmed == prefix)
                || candidate
                    .split_once('@')
                    .is_some_and(|(local_part, _)| local_part == prefix)
        })
    } else {
        candidates.iter().any(|candidate| candidate == &selector)
    }
}

fn route_is_within_auto_approver_prefix(
    approved_prefix: &str,
    route_prefix: &str,
) -> AppResult<bool> {
    if is_exit_route(route_prefix) {
        return Ok(false);
    }

    cidr_contains_prefix(approved_prefix, route_prefix)
}

fn cidr_contains_prefix(container: &str, candidate: &str) -> AppResult<bool> {
    let container = parse_cidr(container)?;
    let candidate = parse_cidr(candidate)?;

    match (container, candidate) {
        (
            ParsedCidr::V4 {
                network: container_network,
                prefix: container_prefix,
            },
            ParsedCidr::V4 {
                network: candidate_network,
                prefix: candidate_prefix,
            },
        ) => {
            if candidate_prefix < container_prefix {
                return Ok(false);
            }

            let mask = if container_prefix == 0 {
                0
            } else {
                u32::MAX << (32 - container_prefix)
            };
            Ok((container_network & mask) == (candidate_network & mask))
        }
        (
            ParsedCidr::V6 {
                network: container_network,
                prefix: container_prefix,
            },
            ParsedCidr::V6 {
                network: candidate_network,
                prefix: candidate_prefix,
            },
        ) => {
            if candidate_prefix < container_prefix {
                return Ok(false);
            }

            let mask = if container_prefix == 0 {
                0
            } else {
                u128::MAX << (128 - container_prefix)
            };
            Ok((container_network & mask) == (candidate_network & mask))
        }
        _ => Ok(false),
    }
}

enum ParsedCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

fn parse_cidr(value: &str) -> AppResult<ParsedCidr> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| AppError::InvalidRequest(format!("route prefix must be CIDR: {value}")))?;

    if let Ok(ipv4) = address.parse::<std::net::Ipv4Addr>() {
        let prefix = prefix.parse::<u8>().map_err(|err| {
            AppError::InvalidRequest(format!("invalid IPv4 route prefix {value}: {err}"))
        })?;
        if prefix > 32 {
            return Err(AppError::InvalidRequest(format!(
                "invalid IPv4 route prefix length: {value}",
            )));
        }

        return Ok(ParsedCidr::V4 {
            network: u32::from(ipv4),
            prefix,
        });
    }

    if let Ok(ipv6) = address.parse::<std::net::Ipv6Addr>() {
        let prefix = prefix.parse::<u8>().map_err(|err| {
            AppError::InvalidRequest(format!("invalid IPv6 route prefix {value}: {err}"))
        })?;
        if prefix > 128 {
            return Err(AppError::InvalidRequest(format!(
                "invalid IPv6 route prefix length: {value}",
            )));
        }

        return Ok(ParsedCidr::V6 {
            network: u128::from_be_bytes(ipv6.octets()),
            prefix,
        });
    }

    Err(AppError::InvalidRequest(format!(
        "route prefix must contain a valid IP network: {value}",
    )))
}

fn compile_rule_for_subject(
    rule: &PolicyRule,
    subject: &Node,
    nodes: &[Node],
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<Option<CompiledAclRule>> {
    let src_ips = expand_source_networks(&rule.sources, nodes, routes_by_node, groups)?;
    if src_ips.is_empty() {
        return Ok(None);
    }

    let mut destinations = BTreeMap::<String, BTreeSet<PolicyPortRange>>::new();
    for destination in &rule.destinations {
        let (selector, ports) = parse_destination_expression(destination)?;
        for network in destination_networks_for_subject(subject, &selector, routes_by_node, groups)?
        {
            destinations
                .entry(network)
                .or_default()
                .extend(ports.iter().cloned());
        }
    }

    if destinations.is_empty() {
        return Ok(None);
    }

    Ok(Some(CompiledAclRule {
        src_ips,
        destinations: destinations
            .into_iter()
            .map(|(network, ports)| CompiledAclDestination {
                network,
                ports: ports.into_iter().collect(),
            })
            .collect(),
    }))
}

fn compile_ip_grant_rules_for_subject(
    grant: &GrantRule,
    subject: &Node,
    nodes: &[Node],
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<Vec<CompiledGrantIpRule>> {
    if grant.ip.is_empty() {
        return Ok(Vec::new());
    }

    if !grant.via.is_empty() {
        return compile_via_ip_grant_rules_for_subject(
            grant,
            subject,
            nodes,
            routes_by_node,
            groups,
        );
    }

    let src_ips = expand_source_networks(&grant.sources, nodes, routes_by_node, groups)?;
    if src_ips.is_empty() {
        return Ok(Vec::new());
    }

    let mut destinations = BTreeMap::<String, BTreeSet<PolicyPortRange>>::new();
    let grant_ip_specs = grant
        .ip
        .iter()
        .map(|spec| parse_grant_ip_spec(spec))
        .collect::<AppResult<Vec<_>>>()?;

    let mut compiled = Vec::new();
    for grant_ip_spec in grant_ip_specs {
        destinations.clear();
        for destination in &grant.destinations {
            let selector = destination.trim();
            for network in
                destination_networks_for_subject(subject, selector, routes_by_node, groups)?
            {
                destinations
                    .entry(network)
                    .or_default()
                    .extend(grant_ip_spec.ports.iter().cloned());
            }
        }

        if destinations.is_empty() {
            continue;
        }

        compiled.push(CompiledGrantIpRule {
            src_ips: src_ips.clone(),
            destinations: destinations
                .iter()
                .map(|(network, ports)| CompiledAclDestination {
                    network: network.clone(),
                    ports: ports.iter().cloned().collect(),
                })
                .collect(),
            ip_protocols: grant_ip_spec.ip_protocols,
        });
    }

    Ok(compiled)
}

fn compile_via_ip_grant_rules_for_subject(
    grant: &GrantRule,
    subject: &Node,
    nodes: &[Node],
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<Vec<CompiledGrantIpRule>> {
    if !node_matches_any_tag(subject, &grant.via) {
        return Ok(Vec::new());
    }

    let src_ips = expand_source_networks(&grant.sources, nodes, routes_by_node, groups)?;
    if src_ips.is_empty() {
        return Ok(Vec::new());
    }

    let via_destinations =
        via_grant_destination_networks_for_subject(grant, subject, routes_by_node, groups)?;
    if via_destinations.is_empty() {
        return Ok(Vec::new());
    }

    let grant_ip_specs = grant
        .ip
        .iter()
        .map(|spec| parse_grant_ip_spec(spec))
        .collect::<AppResult<Vec<_>>>()?;

    Ok(grant_ip_specs
        .into_iter()
        .map(|grant_ip_spec| CompiledGrantIpRule {
            src_ips: src_ips.clone(),
            destinations: via_destinations
                .iter()
                .map(|network| CompiledAclDestination {
                    network: network.clone(),
                    ports: grant_ip_spec.ports.clone(),
                })
                .collect(),
            ip_protocols: grant_ip_spec.ip_protocols,
        })
        .collect())
}

fn compile_app_grant_rules_for_subject(
    grant: &GrantRule,
    subject: &Node,
    nodes: &[Node],
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<Vec<CompiledCapGrantRule>> {
    if !grant.via.is_empty() {
        return Ok(Vec::new());
    }

    let direct_cap_map = grant_cap_map(&grant.app);
    let companion_cap_map = companion_grant_cap_map(&grant.app);
    let src_ips = expand_source_networks(&grant.sources, nodes, routes_by_node, groups)?;
    if src_ips.is_empty() {
        return Ok(Vec::new());
    }
    let direct_destinations = grant_destination_networks_for_subject(
        subject,
        &grant.destinations,
        routes_by_node,
        groups,
    )?;
    let companion_src_ips = expand_grant_destination_source_networks(
        &grant.destinations,
        subject,
        nodes,
        routes_by_node,
        groups,
    )?;
    let companion_destinations =
        grant_destination_networks_for_subject(subject, &grant.sources, routes_by_node, groups)?;

    let mut compiled = Vec::new();

    if !direct_destinations.is_empty() {
        compiled.push(CompiledCapGrantRule {
            src_ips,
            grants: vec![CompiledCapGrant {
                destinations: direct_destinations,
                cap_map: direct_cap_map,
            }],
        });
    }

    if !companion_cap_map.is_empty()
        && !companion_src_ips.is_empty()
        && !companion_destinations.is_empty()
    {
        compiled.push(CompiledCapGrantRule {
            src_ips: companion_src_ips,
            grants: vec![CompiledCapGrant {
                destinations: companion_destinations,
                cap_map: companion_cap_map,
            }],
        });
    }

    Ok(compiled)
}

fn expand_source_networks(
    selectors: &[String],
    nodes: &[Node],
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<Vec<String>> {
    let mut networks = BTreeSet::new();

    for selector in selectors {
        let selector = selector.trim();
        if selector == WILDCARD_SELECTOR {
            return Ok(vec![WILDCARD_SELECTOR.to_string()]);
        }

        if is_raw_network(selector) {
            networks.insert(selector.to_string());
            continue;
        }

        let matched_nodes =
            nodes_matching_selector(selector, None, nodes, routes_by_node, groups, false)?;
        for node in matched_nodes {
            for network in node_source_networks(node, routes_by_node) {
                networks.insert(network);
            }
        }
    }

    Ok(networks.into_iter().collect())
}

fn expand_grant_destination_source_networks(
    selectors: &[String],
    subject: &Node,
    nodes: &[Node],
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<Vec<String>> {
    let mut networks = BTreeSet::new();

    for selector in selectors {
        let selector = selector.trim();
        if selector.is_empty() {
            continue;
        }

        if selector == WILDCARD_SELECTOR {
            for node in nodes {
                for network in node_source_networks(node, routes_by_node) {
                    networks.insert(network);
                }
            }
            continue;
        }

        if selector == AUTOGROUP_SELF {
            for network in node_source_networks(subject, routes_by_node) {
                networks.insert(network);
            }
            continue;
        }

        if is_raw_network(selector) {
            networks.insert(selector.to_string());
            continue;
        }

        let matched_nodes =
            nodes_matching_selector(selector, Some(subject), nodes, routes_by_node, groups, true)?;
        for node in matched_nodes {
            for network in node_source_networks(node, routes_by_node) {
                networks.insert(network);
            }
        }
    }

    Ok(networks.into_iter().collect())
}

fn grant_destination_networks_for_subject(
    subject: &Node,
    selectors: &[String],
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<Vec<String>> {
    let mut destinations = BTreeSet::new();

    for selector in selectors {
        let selector = selector.trim();
        if selector.is_empty() {
            continue;
        }

        for network in destination_networks_for_subject(subject, selector, routes_by_node, groups)?
        {
            destinations.insert(network);
        }
    }

    Ok(destinations.into_iter().collect())
}

fn via_grant_destination_networks_for_subject(
    grant: &GrantRule,
    subject: &Node,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<Vec<String>> {
    let mut destinations = BTreeSet::new();
    let subject_routes = routes_by_node.get(&subject.id).cloned().unwrap_or_default();

    for selector in &grant.destinations {
        let selector = selector.trim();
        if selector.is_empty() || selector == AUTOGROUP_INTERNET {
            continue;
        }

        if is_raw_network(selector) {
            if subject_routes.iter().any(|route| route.prefix == selector) {
                destinations.insert(selector.to_string());
            }
            continue;
        }

        if selector_matches_node(
            selector,
            subject,
            Some(subject),
            routes_by_node,
            groups,
            true,
        )? {
            for route in subject_routes
                .iter()
                .filter(|route| !is_exit_route(&route.prefix))
            {
                destinations.insert(route.prefix.clone());
            }
        }
    }

    Ok(destinations.into_iter().collect())
}

fn grant_cap_map(app: &BTreeMap<String, Vec<Value>>) -> BTreeMap<String, Option<Vec<Value>>> {
    app.iter()
        .map(|(capability, values)| (capability.clone(), Some(values.clone())))
        .collect()
}

fn companion_grant_cap_map(
    app: &BTreeMap<String, Vec<Value>>,
) -> BTreeMap<String, Option<Vec<Value>>> {
    let mut cap_map = BTreeMap::new();

    if app.contains_key("tailscale.com/cap/drive") {
        cap_map.insert("tailscale.com/cap/drive-sharer".to_string(), None);
    }

    if app.contains_key("tailscale.com/cap/relay") {
        cap_map.insert("tailscale.com/cap/relay-target".to_string(), None);
    }

    cap_map
}

fn destination_networks_for_subject(
    subject: &Node,
    selector: &str,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<Vec<String>> {
    if selector == WILDCARD_SELECTOR {
        return Ok(node_destination_networks(subject, routes_by_node));
    }

    if selector == AUTOGROUP_SELF {
        return Ok(node_destination_networks(subject, routes_by_node));
    }

    if selector == AUTOGROUP_INTERNET {
        return Ok(node_exit_route_networks(subject, routes_by_node));
    }

    if is_raw_network(selector) {
        if node_has_network(subject, selector, routes_by_node, false) {
            return Ok(vec![selector.to_string()]);
        }
        return Ok(Vec::new());
    }

    if selector_matches_node(
        selector,
        subject,
        Some(subject),
        routes_by_node,
        groups,
        true,
    )? {
        return Ok(node_destination_networks(subject, routes_by_node));
    }

    Ok(Vec::new())
}

fn rule_connects_nodes(
    rule: &PolicyRule,
    source: &Node,
    destination: &Node,
    subject: &Node,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<bool> {
    let mut source_matches = false;
    for selector in &rule.sources {
        if selector_matches_node(
            selector,
            source,
            Some(subject),
            routes_by_node,
            groups,
            false,
        )? {
            source_matches = true;
            break;
        }
    }
    if !source_matches {
        return Ok(false);
    }

    for destination_expr in &rule.destinations {
        let (selector, _) = parse_destination_expression(destination_expr)?;
        if destination_selector_matches_node_or_routes(
            &selector,
            destination,
            Some(subject),
            routes_by_node,
            groups,
        )? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn grant_connects_nodes(
    grant: &GrantRule,
    source: &Node,
    destination: &Node,
    subject: &Node,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<bool> {
    let mut source_matches = false;
    for selector in &grant.sources {
        if selector_matches_node(
            selector,
            source,
            Some(subject),
            routes_by_node,
            groups,
            false,
        )? {
            source_matches = true;
            break;
        }
    }
    if !source_matches {
        return Ok(false);
    }

    if grant.via.is_empty() {
        for selector in &grant.destinations {
            if destination_selector_matches_node_or_routes(
                selector,
                destination,
                Some(subject),
                routes_by_node,
                groups,
            )? {
                return Ok(true);
            }
        }
        return Ok(false);
    }

    if !node_matches_any_tag(destination, &grant.via) {
        return Ok(false);
    }

    for selector in &grant.destinations {
        if via_destination_selector_matches_node_or_routes(
            selector,
            destination,
            Some(subject),
            routes_by_node,
            groups,
        )? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn rule_grants_route(
    rule: &PolicyRule,
    source: &Node,
    owner: &Node,
    route: &Route,
    subject: &Node,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<bool> {
    let mut source_matches = false;
    for selector in &rule.sources {
        if selector_matches_node(
            selector,
            source,
            Some(subject),
            routes_by_node,
            groups,
            false,
        )? {
            source_matches = true;
            break;
        }
    }
    if !source_matches {
        return Ok(false);
    }

    for destination_expr in &rule.destinations {
        let (selector, _) = parse_destination_expression(destination_expr)?;
        let matches = if selector == WILDCARD_SELECTOR {
            true
        } else if selector == AUTOGROUP_SELF {
            owner.id == subject.id
        } else if selector == AUTOGROUP_INTERNET {
            route.is_exit_node || is_exit_route(&route.prefix)
        } else if is_raw_network(&selector) {
            selector == route.prefix || node_has_network(owner, &selector, routes_by_node, true)
        } else {
            selector_matches_node(
                &selector,
                owner,
                Some(subject),
                routes_by_node,
                groups,
                true,
            )?
        };

        if matches {
            return Ok(true);
        }
    }

    Ok(false)
}

fn grant_grants_route(
    grant: &GrantRule,
    source: &Node,
    owner: &Node,
    route: &Route,
    subject: &Node,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<bool> {
    let mut source_matches = false;
    for selector in &grant.sources {
        if selector_matches_node(
            selector,
            source,
            Some(subject),
            routes_by_node,
            groups,
            false,
        )? {
            source_matches = true;
            break;
        }
    }
    if !source_matches {
        return Ok(false);
    }

    if !grant.via.is_empty() {
        if !node_matches_any_tag(owner, &grant.via) {
            return Ok(false);
        }

        for selector in &grant.destinations {
            let selector = selector.trim();
            let matches = if selector == AUTOGROUP_INTERNET {
                route.is_exit_node || is_exit_route(&route.prefix)
            } else if is_raw_network(selector) {
                selector == route.prefix
            } else {
                selector_matches_node(selector, owner, Some(subject), routes_by_node, groups, true)?
                    && !is_exit_route(&route.prefix)
            };

            if matches {
                return Ok(true);
            }
        }
        return Ok(false);
    }

    for selector in &grant.destinations {
        let matches = if selector == WILDCARD_SELECTOR {
            true
        } else if selector == AUTOGROUP_SELF {
            owner.id == subject.id
        } else if selector == AUTOGROUP_INTERNET {
            route.is_exit_node || is_exit_route(&route.prefix)
        } else if is_raw_network(selector) {
            selector == &route.prefix || node_has_network(owner, selector, routes_by_node, true)
        } else {
            selector_matches_node(selector, owner, Some(subject), routes_by_node, groups, true)?
        };

        if matches {
            return Ok(true);
        }
    }

    Ok(false)
}

fn ssh_rule_targets_node(
    rule: &SshPolicyRule,
    subject: &Node,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<bool> {
    for selector in &rule.destinations {
        if selector == AUTOGROUP_SELF {
            return Ok(true);
        }

        if ssh_selector_matches_node(selector, subject, routes_by_node, groups)? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn compile_ssh_principals(
    selectors: &[String],
    nodes: &[Node],
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<Vec<CompiledSshPrincipal>> {
    let empty_routes = BTreeMap::<u64, Vec<&Route>>::new();
    let mut principals = BTreeSet::new();

    for selector in selectors {
        let selector = selector.trim();
        if selector == WILDCARD_SELECTOR {
            return Ok(vec![CompiledSshPrincipal::Any]);
        }

        if is_raw_network(selector) {
            principals.insert(CompiledSshPrincipal::NodeIp(selector.to_string()));
            continue;
        }

        let matched_nodes =
            nodes_matching_selector(selector, None, nodes, &empty_routes, groups, false)?;
        for node in matched_nodes {
            if let Some(ipv4) = &node.ipv4 {
                principals.insert(CompiledSshPrincipal::NodeIp(ipv4.clone()));
            }
            if let Some(ipv6) = &node.ipv6 {
                principals.insert(CompiledSshPrincipal::NodeIp(ipv6.clone()));
            }
        }
    }

    Ok(principals.into_iter().collect())
}

fn destination_selector_matches_node_or_routes(
    selector: &str,
    destination: &Node,
    subject: Option<&Node>,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<bool> {
    if selector == WILDCARD_SELECTOR {
        return Ok(true);
    }
    if selector == AUTOGROUP_SELF {
        return Ok(subject.is_some_and(|subject| subject.id == destination.id));
    }
    if selector == AUTOGROUP_INTERNET {
        return Ok(node_has_exit_routes(destination, routes_by_node));
    }
    if is_raw_network(selector) {
        return Ok(node_has_network(
            destination,
            selector,
            routes_by_node,
            true,
        ));
    }

    selector_matches_node(selector, destination, subject, routes_by_node, groups, true)
}

fn via_destination_selector_matches_node_or_routes(
    selector: &str,
    destination: &Node,
    subject: Option<&Node>,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<bool> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Ok(false);
    }
    if selector == AUTOGROUP_INTERNET {
        return Ok(node_has_exit_routes(destination, routes_by_node));
    }
    if is_raw_network(selector) {
        return Ok(routes_by_node
            .get(&destination.id)
            .into_iter()
            .flatten()
            .any(|route| route.prefix == selector));
    }

    Ok(
        selector_matches_node(selector, destination, subject, routes_by_node, groups, true)?
            && routes_by_node
                .get(&destination.id)
                .into_iter()
                .flatten()
                .any(|route| !is_exit_route(&route.prefix)),
    )
}

fn nodes_matching_selector<'a>(
    selector: &str,
    subject: Option<&Node>,
    nodes: &'a [Node],
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
    allow_self_destination: bool,
) -> AppResult<Vec<&'a Node>> {
    nodes
        .iter()
        .filter(|node| {
            selector_matches_node(
                selector,
                node,
                subject,
                routes_by_node,
                groups,
                allow_self_destination,
            )
            .unwrap_or(false)
        })
        .collect::<Vec<_>>()
        .pipe(Ok)
}

fn selector_matches_node(
    selector: &str,
    node: &Node,
    subject: Option<&Node>,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
    allow_self_destination: bool,
) -> AppResult<bool> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Ok(false);
    }

    if selector == WILDCARD_SELECTOR {
        return Ok(true);
    }

    if selector == AUTOGROUP_SELF {
        return Ok(allow_self_destination && subject.is_some_and(|subject| subject.id == node.id));
    }

    if selector == AUTOGROUP_INTERNET {
        return Ok(node_has_exit_routes(node, routes_by_node));
    }

    if let Some(name) = selector.strip_prefix(GROUP_PREFIX) {
        return group_matches_node(
            name,
            node,
            subject,
            routes_by_node,
            groups,
            allow_self_destination,
            &mut BTreeSet::new(),
        );
    }

    if selector.starts_with(TAG_PREFIX) {
        return Ok(node.tags.iter().any(|tag| tag == selector));
    }

    if is_raw_network(selector) {
        return Ok(node_has_network(node, selector, routes_by_node, true));
    }

    Ok(selector == node.hostname
        || selector == node.name
        || selector == node.stable_id
        || node.ipv4.as_deref().is_some_and(|ipv4| ipv4 == selector)
        || node.ipv6.as_deref().is_some_and(|ipv6| ipv6 == selector))
}

fn ssh_selector_matches_node(
    selector: &str,
    node: &Node,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
) -> AppResult<bool> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Ok(false);
    }

    if selector == WILDCARD_SELECTOR {
        return Ok(true);
    }

    if selector == AUTOGROUP_SELF {
        return Ok(true);
    }

    if let Some(name) = selector.strip_prefix(GROUP_PREFIX) {
        return group_matches_node(
            name,
            node,
            Some(node),
            routes_by_node,
            groups,
            true,
            &mut BTreeSet::new(),
        );
    }

    if selector.starts_with(TAG_PREFIX) {
        return Ok(node.tags.iter().any(|tag| tag == selector));
    }

    if let Some(ip) = node.ipv4.as_deref()
        && ip_or_cidr_matches(ip, selector)?
    {
        return Ok(true);
    }

    if let Some(ip) = node.ipv6.as_deref()
        && ip_or_cidr_matches(ip, selector)?
    {
        return Ok(true);
    }

    Ok(selector == node.hostname || selector == node.name || selector == node.stable_id)
}

fn compiled_ssh_principal_matches_node(principal: &CompiledSshPrincipal, node: &Node) -> bool {
    match principal {
        CompiledSshPrincipal::Any => true,
        CompiledSshPrincipal::NodeIp(address) => {
            node.ipv4.as_deref().is_some_and(|ipv4| ipv4 == address)
                || node.ipv6.as_deref().is_some_and(|ipv6| ipv6 == address)
        }
    }
}

fn compiled_ssh_local_user(
    ssh_users: &BTreeMap<String, String>,
    requested_user: &str,
) -> Option<String> {
    let mapped = ssh_users
        .get(requested_user)
        .or_else(|| ssh_users.get("*"))?;
    if mapped == "=" {
        return Some(requested_user.to_string());
    }
    if mapped.is_empty() {
        return None;
    }
    Some(mapped.clone())
}

fn group_matches_node(
    group: &str,
    node: &Node,
    subject: Option<&Node>,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    groups: &BTreeMap<String, Vec<String>>,
    allow_self_destination: bool,
    visiting: &mut BTreeSet<String>,
) -> AppResult<bool> {
    if !visiting.insert(group.to_string()) {
        return Err(AppError::InvalidRequest(format!(
            "policy group graph contains a cycle involving {group}",
        )));
    }

    let matches = groups
        .get(group)
        .map(|members| {
            members.iter().any(|member| {
                if let Some(child) = member.strip_prefix(GROUP_PREFIX) {
                    return group_matches_node(
                        child,
                        node,
                        subject,
                        routes_by_node,
                        groups,
                        allow_self_destination,
                        visiting,
                    )
                    .unwrap_or(false);
                }

                selector_matches_node(
                    member,
                    node,
                    subject,
                    routes_by_node,
                    groups,
                    allow_self_destination,
                )
                .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    visiting.remove(group);
    Ok(matches)
}

fn node_has_network(
    node: &Node,
    selector: &str,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    include_exit_routes: bool,
) -> bool {
    node_source_networks_with_exit(node, routes_by_node, include_exit_routes)
        .into_iter()
        .any(|network| network == selector)
        || node.ipv4.as_deref().is_some_and(|ipv4| ipv4 == selector)
        || node.ipv6.as_deref().is_some_and(|ipv6| ipv6 == selector)
}

fn node_source_networks(node: &Node, routes_by_node: &BTreeMap<u64, Vec<&Route>>) -> Vec<String> {
    node_source_networks_with_exit(node, routes_by_node, false)
}

fn node_destination_networks(
    node: &Node,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
) -> Vec<String> {
    node_source_networks_with_exit(node, routes_by_node, false)
}

fn node_exit_route_networks(
    node: &Node,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
) -> Vec<String> {
    routes_by_node
        .get(&node.id)
        .into_iter()
        .flatten()
        .filter(|route| is_exit_route(&route.prefix))
        .map(|route| route.prefix.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn node_has_exit_routes(node: &Node, routes_by_node: &BTreeMap<u64, Vec<&Route>>) -> bool {
    routes_by_node
        .get(&node.id)
        .into_iter()
        .flatten()
        .any(|route| is_exit_route(&route.prefix))
}

fn node_source_networks_with_exit(
    node: &Node,
    routes_by_node: &BTreeMap<u64, Vec<&Route>>,
    include_exit_routes: bool,
) -> Vec<String> {
    let mut networks = BTreeSet::new();
    if let Some(ipv4) = &node.ipv4 {
        networks.insert(ipv4.clone());
    }
    if let Some(ipv6) = &node.ipv6 {
        networks.insert(ipv6.clone());
    }

    if let Some(routes) = routes_by_node.get(&node.id) {
        for route in routes {
            if !include_exit_routes && is_exit_route(&route.prefix) {
                continue;
            }
            networks.insert(route.prefix.clone());
        }
    }

    networks.into_iter().collect()
}

fn routes_by_node(routes: &[Route]) -> BTreeMap<u64, Vec<&Route>> {
    let mut by_node = BTreeMap::<u64, Vec<&Route>>::new();
    for route in routes {
        by_node.entry(route.node_id).or_default().push(route);
    }
    by_node
}

fn is_raw_network(value: &str) -> bool {
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }

    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };

    if let Ok(ipv4) = address.parse::<std::net::Ipv4Addr>() {
        let _ = ipv4;
        return prefix.parse::<u8>().is_ok_and(|bits| bits <= 32);
    }

    if let Ok(ipv6) = address.parse::<std::net::Ipv6Addr>() {
        let _ = ipv6;
        return prefix.parse::<u8>().is_ok_and(|bits| bits <= 128);
    }

    false
}

fn ip_or_cidr_matches(ip: &str, selector: &str) -> AppResult<bool> {
    let node_ip = ip.parse::<std::net::IpAddr>().map_err(|err| {
        AppError::InvalidRequest(format!("node contains invalid IP address {ip}: {err}"))
    })?;

    if let Ok(target) = selector.parse::<std::net::IpAddr>() {
        return Ok(node_ip == target);
    }

    let Some((network, prefix)) = selector.split_once('/') else {
        return Ok(false);
    };

    match (
        network.parse::<std::net::IpAddr>(),
        prefix.parse::<u8>(),
        node_ip,
    ) {
        (Ok(std::net::IpAddr::V4(network)), Ok(bits), std::net::IpAddr::V4(node_ip))
            if bits <= 32 =>
        {
            let network = u32::from(network);
            let node_ip = u32::from(node_ip);
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            Ok((network & mask) == (node_ip & mask))
        }
        (Ok(std::net::IpAddr::V6(network)), Ok(bits), std::net::IpAddr::V6(node_ip))
            if bits <= 128 =>
        {
            let network = u128::from_be_bytes(network.octets());
            let node_ip = u128::from_be_bytes(node_ip.octets());
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            Ok((network & mask) == (node_ip & mask))
        }
        _ => Ok(false),
    }
}

fn is_exit_route(prefix: &str) -> bool {
    prefix == "0.0.0.0/0" || prefix == "::/0"
}

fn node_matches_any_tag(node: &Node, tags: &[String]) -> bool {
    tags.iter()
        .map(|tag| tag.trim())
        .filter(|tag| !tag.is_empty())
        .any(|tag| node.tags.iter().any(|node_tag| node_tag == tag))
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn node(id: u64, hostname: &str, ipv4: &str, tags: &[&str]) -> Node {
        Node {
            id,
            stable_id: format!("stable-{id}"),
            name: hostname.to_string(),
            hostname: hostname.to_string(),
            auth_key_id: None,
            principal_id: None,
            ipv4: Some(ipv4.to_string()),
            ipv6: None,
            status: crate::domain::NodeStatus::Online,
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            tag_source: if tags.is_empty() {
                crate::domain::NodeTagSource::None
            } else {
                crate::domain::NodeTagSource::Request
            },
            last_seen_unix_secs: None,
        }
    }

    fn node_with_principal(
        id: u64,
        hostname: &str,
        ipv4: &str,
        principal_id: u64,
        tags: &[&str],
    ) -> Node {
        Node {
            principal_id: Some(principal_id),
            ..node(id, hostname, ipv4, tags)
        }
    }

    fn principal(id: u64, login_name: &str, email: Option<&str>) -> Principal {
        Principal {
            id,
            provider: "oidc".to_string(),
            issuer: Some("https://issuer.example.com".to_string()),
            subject: Some(format!("subject-{id}")),
            login_name: login_name.to_string(),
            display_name: login_name.to_string(),
            email: email.map(str::to_string),
            groups: Vec::new(),
            created_at_unix_secs: 1,
        }
    }

    fn route(id: u64, node_id: u64, prefix: &str) -> Route {
        Route {
            id,
            node_id,
            prefix: prefix.to_string(),
            advertised: true,
            approval: crate::domain::RouteApproval::Approved,
            approved_by_policy: false,
            is_exit_node: false,
        }
    }

    fn exit_route(id: u64, node_id: u64, prefix: &str) -> Route {
        Route {
            id,
            node_id,
            prefix: prefix.to_string(),
            advertised: true,
            approval: crate::domain::RouteApproval::Approved,
            approved_by_policy: false,
            is_exit_node: true,
        }
    }

    #[test]
    fn validate_rejects_non_accept_actions() {
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: vec![PolicyRule {
                action: "deny".to_string(),
                sources: vec!["*".to_string()],
                destinations: vec!["*:443".to_string()],
            }],
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        assert!(policy.validate().is_err());
    }

    #[test]
    fn evaluate_compiles_packet_filter_for_destination_node() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let server = node(2, "server", "100.64.0.20", &["tag:server"]);
        let policy = AclPolicy {
            groups: vec![PolicySubject {
                name: "prod".to_string(),
                members: vec!["tag:client".to_string()],
            }],
            rules: vec![PolicyRule {
                action: "accept".to_string(),
                sources: vec!["group:prod".to_string()],
                destinations: vec!["tag:server:22,443".to_string()],
            }],
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        let view = policy.evaluate_for_node(
            &server,
            &[client.clone(), server.clone()],
            &[route(10, server.id, "10.10.0.0/24")],
        )?;

        assert_eq!(view.visible_peer_ids, BTreeSet::from([client.id]));
        assert_eq!(view.visible_route_ids, BTreeSet::new());
        assert_eq!(
            view.packet_rules,
            vec![CompiledAclRule {
                src_ips: vec!["100.64.0.10".to_string()],
                destinations: vec![
                    CompiledAclDestination {
                        network: "10.10.0.0/24".to_string(),
                        ports: vec![
                            PolicyPortRange {
                                first: 22,
                                last: 22
                            },
                            PolicyPortRange {
                                first: 443,
                                last: 443
                            }
                        ],
                    },
                    CompiledAclDestination {
                        network: "100.64.0.20".to_string(),
                        ports: vec![
                            PolicyPortRange {
                                first: 22,
                                last: 22
                            },
                            PolicyPortRange {
                                first: 443,
                                last: 443
                            }
                        ],
                    },
                ],
            }]
        );
        Ok(())
    }

    #[test]
    fn evaluate_filters_visible_peers_and_routes_for_source_node() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let server = node(2, "server", "100.64.0.20", &["tag:server"]);
        let other = node(3, "other", "100.64.0.30", &["tag:other"]);
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: vec![PolicyRule {
                action: "accept".to_string(),
                sources: vec!["tag:client".to_string()],
                destinations: vec!["tag:server:80-81".to_string()],
            }],
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };
        let route = route(20, server.id, "10.20.0.0/24");

        let view = policy.evaluate_for_node(
            &client,
            &[client.clone(), server.clone(), other],
            std::slice::from_ref(&route),
        )?;

        assert_eq!(view.visible_peer_ids, BTreeSet::from([server.id]));
        assert_eq!(view.visible_route_ids, BTreeSet::from([route.id]));
        assert!(view.packet_rules.is_empty());
        Ok(())
    }

    #[test]
    fn default_allow_policy_keeps_allow_all_behavior() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &[]);
        let server = node(2, "server", "100.64.0.20", &[]);

        let view = AclPolicy::default().evaluate_for_node(
            &client,
            &[client.clone(), server.clone()],
            &[],
        )?;

        assert_eq!(view.visible_peer_ids, BTreeSet::from([server.id]));
        assert_eq!(
            view.packet_rules,
            vec![CompiledAclRule {
                src_ips: vec!["*".to_string()],
                destinations: vec![CompiledAclDestination {
                    network: "*".to_string(),
                    ports: vec![PolicyPortRange {
                        first: 0,
                        last: u16::MAX,
                    }],
                }],
            }]
        );
        Ok(())
    }

    #[test]
    fn auto_approvers_validate_rejects_non_user_group_or_tag_selectors() {
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy {
                routes: BTreeMap::from([(
                    "10.0.0.0/8".to_string(),
                    vec!["100.64.0.10".to_string()],
                )]),
                exit_node: Vec::new(),
            },
            ssh_rules: Vec::new(),
        };

        assert!(policy.validate().is_err());
    }

    #[test]
    fn auto_approves_subnet_route_for_group_member_principal() -> TestResult {
        let router = node_with_principal(1, "router", "100.64.0.10", 10, &[]);
        let principal = principal(10, "alice@example.com", Some("alice@example.com"));
        let route = Route {
            id: 1,
            node_id: router.id,
            prefix: "10.1.0.0/24".to_string(),
            advertised: true,
            approval: crate::domain::RouteApproval::Pending,
            approved_by_policy: false,
            is_exit_node: false,
        };
        let policy = AclPolicy {
            groups: vec![PolicySubject {
                name: "admins".to_string(),
                members: vec!["alice@".to_string()],
            }],
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy {
                routes: BTreeMap::from([(
                    "10.0.0.0/8".to_string(),
                    vec!["group:admins".to_string()],
                )]),
                exit_node: Vec::new(),
            },
            ssh_rules: Vec::new(),
        };

        assert!(policy.auto_approves_route(&router, Some(&principal), &route)?);
        Ok(())
    }

    #[test]
    fn auto_approvers_do_not_treat_tagged_nodes_as_group_members() -> TestResult {
        let tagged_router = node_with_principal(1, "router", "100.64.0.10", 10, &["tag:router"]);
        let principal = principal(10, "alice@example.com", Some("alice@example.com"));
        let route = Route {
            id: 2,
            node_id: tagged_router.id,
            prefix: "10.2.0.0/24".to_string(),
            advertised: true,
            approval: crate::domain::RouteApproval::Pending,
            approved_by_policy: false,
            is_exit_node: false,
        };
        let policy = AclPolicy {
            groups: vec![PolicySubject {
                name: "ops".to_string(),
                members: vec!["alice@".to_string()],
            }],
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy {
                routes: BTreeMap::from([("10.0.0.0/8".to_string(), vec!["group:ops".to_string()])]),
                exit_node: Vec::new(),
            },
            ssh_rules: Vec::new(),
        };

        assert!(!policy.auto_approves_route(&tagged_router, Some(&principal), &route)?);
        Ok(())
    }

    #[test]
    fn auto_approvers_allow_tagged_exit_nodes_only_via_exit_node_policy() -> TestResult {
        let exit_node = node(1, "exit", "100.64.0.10", &["tag:exit"]);
        let exit_route = Route {
            id: 3,
            node_id: exit_node.id,
            prefix: "0.0.0.0/0".to_string(),
            advertised: true,
            approval: crate::domain::RouteApproval::Pending,
            approved_by_policy: false,
            is_exit_node: true,
        };
        let route_policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy {
                routes: BTreeMap::from([("0.0.0.0/0".to_string(), vec!["tag:exit".to_string()])]),
                exit_node: Vec::new(),
            },
            ssh_rules: Vec::new(),
        };
        let exit_policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy {
                routes: BTreeMap::new(),
                exit_node: vec!["tag:exit".to_string()],
            },
            ssh_rules: Vec::new(),
        };

        assert!(!route_policy.auto_approves_route(&exit_node, None, &exit_route)?);
        assert!(exit_policy.auto_approves_route(&exit_node, None, &exit_route)?);
        Ok(())
    }

    #[test]
    fn validate_rejects_ssh_accept_rules_without_user_mappings() {
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: vec![SshPolicyRule {
                action: SshPolicyAction::Accept,
                sources: vec!["tag:client".to_string()],
                destinations: vec!["tag:server".to_string()],
                ssh_users: BTreeMap::new(),
                accept_env: Vec::new(),
                message: None,
                allow_agent_forwarding: true,
                allow_local_port_forwarding: true,
                allow_remote_port_forwarding: true,
                session_duration_secs: None,
                check_period_secs: None,
            }],
        };

        assert!(policy.validate().is_err());
    }

    #[test]
    fn evaluate_ssh_policy_compiles_accept_rules_for_target_node() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let server = node(2, "server", "100.64.0.20", &["tag:server"]);
        let policy = AclPolicy {
            groups: vec![PolicySubject {
                name: "prod".to_string(),
                members: vec!["tag:client".to_string()],
            }],
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: vec![SshPolicyRule {
                action: SshPolicyAction::Accept,
                sources: vec!["group:prod".to_string()],
                destinations: vec!["tag:server".to_string()],
                ssh_users: BTreeMap::from([
                    ("*".to_string(), "=".to_string()),
                    ("root".to_string(), "".to_string()),
                ]),
                accept_env: vec!["TERM".to_string()],
                message: Some("SSH access granted".to_string()),
                allow_agent_forwarding: true,
                allow_local_port_forwarding: false,
                allow_remote_port_forwarding: true,
                session_duration_secs: Some(3600),
                check_period_secs: None,
            }],
        };

        let view = policy.evaluate_ssh_for_node(&server, &[client, server.clone()], &[])?;

        assert_eq!(
            view.rules,
            vec![CompiledSshRule {
                principals: vec![CompiledSshPrincipal::NodeIp("100.64.0.10".to_string())],
                ssh_users: BTreeMap::from([
                    ("*".to_string(), "=".to_string()),
                    ("root".to_string(), "".to_string()),
                ]),
                action: CompiledSshAction {
                    message: Some("SSH access granted".to_string()),
                    reject: false,
                    accept: true,
                    check: false,
                    check_period_secs: None,
                    session_duration_secs: Some(3600),
                    allow_agent_forwarding: true,
                    allow_local_port_forwarding: false,
                    allow_remote_port_forwarding: true,
                },
                accept_env: vec!["TERM".to_string()],
            }]
        );
        Ok(())
    }

    #[test]
    fn evaluate_ssh_policy_uses_any_principal_for_wildcard_source() -> TestResult {
        let server = node(2, "server", "100.64.0.20", &["tag:server"]);
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: vec![SshPolicyRule {
                action: SshPolicyAction::Reject,
                sources: vec!["*".to_string()],
                destinations: vec!["autogroup:self".to_string()],
                ssh_users: BTreeMap::new(),
                accept_env: Vec::new(),
                message: Some("SSH disabled".to_string()),
                allow_agent_forwarding: true,
                allow_local_port_forwarding: true,
                allow_remote_port_forwarding: true,
                session_duration_secs: None,
                check_period_secs: None,
            }],
        };

        let view = policy.evaluate_ssh_for_node(&server, std::slice::from_ref(&server), &[])?;

        assert_eq!(view.rules[0].principals, vec![CompiledSshPrincipal::Any]);
        assert!(view.rules[0].action.reject);
        Ok(())
    }

    #[test]
    fn validate_rejects_check_period_for_non_check_action() {
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: vec![SshPolicyRule {
                action: SshPolicyAction::Accept,
                sources: vec!["tag:client".to_string()],
                destinations: vec!["tag:server".to_string()],
                ssh_users: BTreeMap::from([("*".to_string(), "=".to_string())]),
                accept_env: Vec::new(),
                message: None,
                allow_agent_forwarding: true,
                allow_local_port_forwarding: true,
                allow_remote_port_forwarding: true,
                session_duration_secs: None,
                check_period_secs: Some(300),
            }],
        };

        assert!(policy.validate().is_err());
    }

    #[test]
    fn ssh_check_period_for_pair_returns_explicit_period() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let server = node(2, "server", "100.64.0.20", &["tag:server"]);
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: vec![SshPolicyRule {
                action: SshPolicyAction::Check,
                sources: vec!["tag:client".to_string()],
                destinations: vec!["tag:server".to_string()],
                ssh_users: BTreeMap::from([("*".to_string(), "=".to_string())]),
                accept_env: Vec::new(),
                message: None,
                allow_agent_forwarding: true,
                allow_local_port_forwarding: true,
                allow_remote_port_forwarding: true,
                session_duration_secs: None,
                check_period_secs: Some(7_200),
            }],
        };

        let period = policy.ssh_check_period_for_pair(
            &client,
            &server,
            &[client.clone(), server.clone()],
            &[],
        )?;

        assert_eq!(period, Some(7_200));
        Ok(())
    }

    #[test]
    fn ssh_check_action_for_connection_matches_requested_and_local_user() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let server = node(2, "server", "100.64.0.20", &["tag:server"]);
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: vec![SshPolicyRule {
                action: SshPolicyAction::Check,
                sources: vec!["tag:client".to_string()],
                destinations: vec!["tag:server".to_string()],
                ssh_users: BTreeMap::from([
                    ("alice".to_string(), "postgres".to_string()),
                    ("*".to_string(), "=".to_string()),
                ]),
                accept_env: Vec::new(),
                message: None,
                allow_agent_forwarding: true,
                allow_local_port_forwarding: true,
                allow_remote_port_forwarding: true,
                session_duration_secs: None,
                check_period_secs: Some(900),
            }],
        };

        let matched = policy
            .ssh_check_action_for_connection(
                &client,
                &server,
                "alice",
                Some("postgres"),
                &[client.clone(), server.clone()],
                &[],
            )?
            .ok_or_else(|| std::io::Error::other("ssh action should match"))?;

        assert!(matched.0.check);
        assert_eq!(matched.1, "postgres");
        Ok(())
    }

    #[test]
    fn ssh_check_action_for_connection_rejects_local_user_mismatch() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let server = node(2, "server", "100.64.0.20", &["tag:server"]);
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: vec![SshPolicyRule {
                action: SshPolicyAction::Check,
                sources: vec!["tag:client".to_string()],
                destinations: vec!["tag:server".to_string()],
                ssh_users: BTreeMap::from([("alice".to_string(), "postgres".to_string())]),
                accept_env: Vec::new(),
                message: None,
                allow_agent_forwarding: true,
                allow_local_port_forwarding: true,
                allow_remote_port_forwarding: true,
                session_duration_secs: None,
                check_period_secs: Some(900),
            }],
        };

        let matched = policy.ssh_check_action_for_connection(
            &client,
            &server,
            "alice",
            Some("root"),
            &[client.clone(), server.clone()],
            &[],
        )?;

        assert!(matched.is_none());
        Ok(())
    }

    #[test]
    fn validate_rejects_invalid_grant_via_selector() {
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: vec![GrantRule {
                sources: vec!["tag:client".to_string()],
                destinations: vec!["tag:server".to_string()],
                ip: vec!["tcp:443".to_string()],
                via: vec!["group:routers".to_string()],
                app: BTreeMap::new(),
            }],
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        assert!(policy.validate().is_err());
    }

    #[test]
    fn evaluate_grant_ip_compiles_filter_rule_for_destination_node() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let server = node(2, "server", "100.64.0.20", &["tag:server"]);
        let subnet = route(10, server.id, "10.10.0.0/24");
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: vec![GrantRule {
                sources: vec!["tag:client".to_string()],
                destinations: vec!["tag:server".to_string()],
                ip: vec!["tcp:443".to_string(), "icmp:*".to_string()],
                via: Vec::new(),
                app: BTreeMap::new(),
            }],
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        let view = policy.evaluate_for_node(
            &server,
            &[client.clone(), server.clone()],
            std::slice::from_ref(&subnet),
        )?;

        assert_eq!(view.visible_peer_ids, BTreeSet::from([client.id]));
        assert_eq!(view.grant_ip_rules.len(), 2);
        assert_eq!(
            view.grant_ip_rules[0],
            CompiledGrantIpRule {
                src_ips: vec!["100.64.0.10".to_string()],
                destinations: vec![
                    CompiledAclDestination {
                        network: "10.10.0.0/24".to_string(),
                        ports: vec![PolicyPortRange {
                            first: 443,
                            last: 443,
                        }],
                    },
                    CompiledAclDestination {
                        network: "100.64.0.20".to_string(),
                        ports: vec![PolicyPortRange {
                            first: 443,
                            last: 443,
                        }],
                    },
                ],
                ip_protocols: vec![6],
            }
        );
        assert_eq!(view.grant_ip_rules[1].ip_protocols, vec![1]);
        assert_eq!(
            view.grant_ip_rules[1].destinations[0].ports,
            vec![PolicyPortRange {
                first: 0,
                last: u16::MAX,
            }]
        );
        Ok(())
    }

    #[test]
    fn evaluate_grants_compile_cap_grants_for_destination_node() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let server = node(2, "server", "100.64.0.20", &["tag:server"]);
        let subnet = route(10, server.id, "10.10.0.0/24");
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: vec![GrantRule {
                sources: vec!["tag:client".to_string()],
                destinations: vec!["tag:server".to_string()],
                ip: Vec::new(),
                via: Vec::new(),
                app: BTreeMap::from([(
                    "tailscale.com/cap/webui".to_string(),
                    vec![serde_json::json!({
                        "ports": [443],
                    })],
                )]),
            }],
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        let view = policy.evaluate_for_node(
            &server,
            &[client.clone(), server.clone()],
            std::slice::from_ref(&subnet),
        )?;

        assert_eq!(view.visible_peer_ids, BTreeSet::from([client.id]));
        assert_eq!(view.cap_grant_rules.len(), 1);
        assert_eq!(
            view.cap_grant_rules[0],
            CompiledCapGrantRule {
                src_ips: vec!["100.64.0.10".to_string()],
                grants: vec![CompiledCapGrant {
                    destinations: vec!["10.10.0.0/24".to_string(), "100.64.0.20".to_string()],
                    cap_map: BTreeMap::from([(
                        "tailscale.com/cap/webui".to_string(),
                        Some(vec![serde_json::json!({
                            "ports": [443],
                        })]),
                    )]),
                }],
            }
        );
        Ok(())
    }

    #[test]
    fn evaluate_drive_grants_emit_companion_capability_for_source_node() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let server = node(2, "server", "100.64.0.20", &["tag:server"]);
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: vec![GrantRule {
                sources: vec!["tag:client".to_string()],
                destinations: vec!["tag:server".to_string()],
                ip: Vec::new(),
                via: Vec::new(),
                app: BTreeMap::from([(
                    "tailscale.com/cap/drive".to_string(),
                    vec![serde_json::json!({
                        "shares": ["docs"],
                    })],
                )]),
            }],
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        let view = policy.evaluate_for_node(&client, &[client.clone(), server.clone()], &[])?;

        assert_eq!(view.visible_peer_ids, BTreeSet::from([server.id]));
        assert_eq!(view.cap_grant_rules.len(), 1);
        assert_eq!(
            view.cap_grant_rules[0],
            CompiledCapGrantRule {
                src_ips: vec!["100.64.0.20".to_string()],
                grants: vec![CompiledCapGrant {
                    destinations: vec!["100.64.0.10".to_string()],
                    cap_map: BTreeMap::from([
                        ("tailscale.com/cap/drive-sharer".to_string(), None,)
                    ]),
                }],
            }
        );
        Ok(())
    }

    #[test]
    fn evaluate_grants_make_subnet_routes_visible_to_source_node() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let router = node(2, "router", "100.64.0.20", &["tag:router"]);
        let subnet = route(20, router.id, "10.20.0.0/24");
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: vec![GrantRule {
                sources: vec!["tag:client".to_string()],
                destinations: vec!["10.20.0.0/24".to_string()],
                ip: Vec::new(),
                via: Vec::new(),
                app: BTreeMap::from([("tailscale.com/cap/webui".to_string(), Vec::new())]),
            }],
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        let view = policy.evaluate_for_node(
            &client,
            &[client.clone(), router.clone()],
            std::slice::from_ref(&subnet),
        )?;

        assert_eq!(view.visible_peer_ids, BTreeSet::from([router.id]));
        assert_eq!(view.visible_route_ids, BTreeSet::from([subnet.id]));
        Ok(())
    }

    #[test]
    fn evaluate_via_grant_only_exposes_matching_router_and_route() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let relay_router = node(2, "relay-router", "100.64.0.20", &["tag:relay"]);
        let other_router = node(3, "other-router", "100.64.0.30", &["tag:other"]);
        let relay_route = route(20, relay_router.id, "10.20.0.0/24");
        let other_route = route(21, other_router.id, "10.20.0.0/24");
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: vec![GrantRule {
                sources: vec!["tag:client".to_string()],
                destinations: vec!["10.20.0.0/24".to_string()],
                ip: vec!["tcp:443".to_string()],
                via: vec!["tag:relay".to_string()],
                app: BTreeMap::new(),
            }],
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        let client_view = policy.evaluate_for_node(
            &client,
            &[client.clone(), relay_router.clone(), other_router.clone()],
            &[relay_route.clone(), other_route.clone()],
        )?;
        let relay_view = policy.evaluate_for_node(
            &relay_router,
            &[client.clone(), relay_router.clone(), other_router.clone()],
            &[relay_route.clone(), other_route.clone()],
        )?;
        let other_view = policy.evaluate_for_node(
            &other_router,
            &[client.clone(), relay_router.clone(), other_router.clone()],
            &[relay_route.clone(), other_route.clone()],
        )?;

        assert_eq!(
            client_view.visible_peer_ids,
            BTreeSet::from([relay_router.id])
        );
        assert_eq!(
            client_view.visible_route_ids,
            BTreeSet::from([relay_route.id])
        );
        assert_eq!(relay_view.visible_peer_ids, BTreeSet::from([client.id]));
        assert_eq!(
            relay_view.grant_ip_rules,
            vec![CompiledGrantIpRule {
                src_ips: vec!["100.64.0.10".to_string()],
                destinations: vec![CompiledAclDestination {
                    network: "10.20.0.0/24".to_string(),
                    ports: vec![PolicyPortRange {
                        first: 443,
                        last: 443,
                    }],
                }],
                ip_protocols: vec![6],
            }]
        );
        assert!(other_view.grant_ip_rules.is_empty());
        Ok(())
    }

    #[test]
    fn evaluate_via_internet_grant_exposes_exit_routes_without_filter_rules() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let exit_node = node(2, "exit", "100.64.0.20", &["tag:exit"]);
        let exit_v4 = exit_route(30, exit_node.id, "0.0.0.0/0");
        let exit_v6 = exit_route(31, exit_node.id, "::/0");
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: vec![GrantRule {
                sources: vec!["tag:client".to_string()],
                destinations: vec![AUTOGROUP_INTERNET.to_string()],
                ip: vec!["*".to_string()],
                via: vec!["tag:exit".to_string()],
                app: BTreeMap::new(),
            }],
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        let client_view = policy.evaluate_for_node(
            &client,
            &[client.clone(), exit_node.clone()],
            &[exit_v4.clone(), exit_v6.clone()],
        )?;
        let exit_view = policy.evaluate_for_node(
            &exit_node,
            &[client.clone(), exit_node.clone()],
            &[exit_v4.clone(), exit_v6.clone()],
        )?;

        assert_eq!(client_view.visible_peer_ids, BTreeSet::from([exit_node.id]));
        assert_eq!(
            client_view.visible_route_ids,
            BTreeSet::from([exit_v4.id, exit_v6.id])
        );
        assert!(exit_view.grant_ip_rules.is_empty());
        Ok(())
    }

    #[test]
    fn evaluate_app_only_via_grant_does_not_emit_cap_grants() -> TestResult {
        let client = node(1, "client", "100.64.0.10", &["tag:client"]);
        let relay_router = node(2, "relay-router", "100.64.0.20", &["tag:relay"]);
        let relay_route = route(40, relay_router.id, "10.40.0.0/24");
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: vec![GrantRule {
                sources: vec!["tag:client".to_string()],
                destinations: vec!["10.40.0.0/24".to_string()],
                ip: Vec::new(),
                via: vec!["tag:relay".to_string()],
                app: BTreeMap::from([("tailscale.com/cap/webui".to_string(), Vec::new())]),
            }],
            tag_owners: BTreeMap::new(),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        let view = policy.evaluate_for_node(
            &relay_router,
            &[client.clone(), relay_router.clone()],
            std::slice::from_ref(&relay_route),
        )?;

        assert!(view.cap_grant_rules.is_empty());
        Ok(())
    }

    #[test]
    fn approved_request_tags_allow_username_owned_tags() -> TestResult {
        let node = node_with_principal(1, "workstation", "100.64.0.10", 10, &[]);
        let principal = principal(10, "alice@example.com", Some("alice@example.com"));
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::from([("tag:prod".to_string(), vec!["alice@".to_string()])]),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        let approved =
            policy.approved_request_tags(&node, Some(&principal), &["tag:prod".to_string()])?;

        assert_eq!(approved, vec!["tag:prod".to_string()]);
        Ok(())
    }

    #[test]
    fn approved_request_tags_allow_group_owned_tags() -> TestResult {
        let node = node_with_principal(1, "workstation", "100.64.0.10", 10, &[]);
        let principal = principal(10, "alice@example.com", Some("alice@example.com"));
        let policy = AclPolicy {
            groups: vec![PolicySubject {
                name: "eng".to_string(),
                members: vec!["alice@".to_string()],
            }],
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::from([("tag:relay".to_string(), vec!["group:eng".to_string()])]),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        let approved =
            policy.approved_request_tags(&node, Some(&principal), &["tag:relay".to_string()])?;

        assert_eq!(approved, vec!["tag:relay".to_string()]);
        Ok(())
    }

    #[test]
    fn approved_request_tags_allow_nested_tag_owners() -> TestResult {
        let node = node_with_principal(1, "workstation", "100.64.0.10", 10, &[]);
        let principal = principal(10, "alice@example.com", Some("alice@example.com"));
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::from([
                ("tag:relay".to_string(), vec!["alice@".to_string()]),
                ("tag:router".to_string(), vec!["tag:relay".to_string()]),
            ]),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        let approved = policy.approved_request_tags(
            &node,
            Some(&principal),
            &["tag:relay".to_string(), "tag:router".to_string()],
        )?;

        assert_eq!(
            approved,
            vec!["tag:relay".to_string(), "tag:router".to_string()]
        );
        Ok(())
    }

    #[test]
    fn approved_request_tags_use_existing_tag_identity() -> TestResult {
        let node = node(1, "router", "100.64.0.10", &["tag:relay"]);
        let policy = AclPolicy {
            groups: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            tag_owners: BTreeMap::from([
                ("tag:relay".to_string(), vec!["alice@".to_string()]),
                ("tag:router".to_string(), vec!["tag:relay".to_string()]),
            ]),
            auto_approvers: AutoApproverPolicy::default(),
            ssh_rules: Vec::new(),
        };

        let approved = policy.approved_request_tags(&node, None, &["tag:router".to_string()])?;

        assert_eq!(approved, vec!["tag:router".to_string()]);
        Ok(())
    }
}
