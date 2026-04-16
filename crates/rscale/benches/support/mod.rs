#![allow(dead_code)]

use std::collections::BTreeMap;
use std::env;
use std::time::Duration;

use criterion::Criterion;
use rscale::domain::{
    AclPolicy, AutoApproverPolicy, GrantRule, Node, NodeStatus, NodeTagSource, PolicyRule,
    PolicySubject, Route, RouteApproval,
};
use rscale::protocol::types::{
    ControlClientVersion, ControlDerpMap, ControlDerpNode, ControlDerpRegion,
    ControlDisplayMessage, ControlDisplayMessageAction, ControlDisplayMessageSeverity,
    ControlDnsConfig, ControlDnsResolver, ControlFilterRule, ControlNetPortRange, ControlNode,
    ControlPortRange, ControlUserProfile, EarlyNoise, MapResponse, allow_all_packet_filter,
};
use serde_json::json;

const TEAM_COUNT: usize = 8;

pub fn criterion_config() -> Criterion {
    let criterion = if env::var_os("RSCALE_BENCH_FULL").is_some() {
        Criterion::default()
    } else {
        Criterion::default()
            .sample_size(20)
            .warm_up_time(Duration::from_millis(200))
            .measurement_time(Duration::from_millis(800))
            .nresamples(20)
            .without_plots()
    };

    criterion.configure_from_args()
}

pub fn sample_policy(rule_count: usize) -> AclPolicy {
    let groups = (0..TEAM_COUNT)
        .map(|team| PolicySubject {
            name: format!("team-{team}"),
            members: vec![format!("tag:team-{team}")],
        })
        .collect();

    let rules = (0..rule_count)
        .map(|idx| PolicyRule {
            action: "accept".to_string(),
            sources: vec![format!("group:team-{}", idx % TEAM_COUNT)],
            destinations: vec![format!("tag:team-{}:22,80,443", (idx + 1) % TEAM_COUNT)],
        })
        .collect();

    let grants = (0..rule_count.saturating_div(4).max(1))
        .map(|idx| GrantRule {
            sources: vec![format!("group:team-{}", idx % TEAM_COUNT)],
            destinations: vec![format!("tag:team-{}", (idx + 2) % TEAM_COUNT)],
            ip: vec!["tcp:8443".to_string(), "udp:41641".to_string()],
            via: Vec::new(),
            app: BTreeMap::from([(
                "tailscale.com/cap/drive".to_string(),
                vec![json!({"share":"team"})],
            )]),
        })
        .collect();

    AclPolicy {
        groups,
        rules,
        grants,
        tag_owners: BTreeMap::new(),
        auto_approvers: AutoApproverPolicy::default(),
        ssh_rules: Vec::new(),
    }
}

pub fn sample_nodes(count: usize) -> Vec<Node> {
    (0..count)
        .map(|idx| {
            let host_id = idx + 1;
            let team = idx % TEAM_COUNT;
            Node {
                id: host_id as u64,
                stable_id: format!("node-{host_id:04}"),
                name: format!("node-{host_id:04}"),
                hostname: format!("node-{host_id:04}.corp.internal"),
                auth_key_id: None,
                principal_id: Some((team + 1) as u64),
                ipv4: Some(ipv4_for_index(host_id)),
                ipv6: Some(format!("fd7a:115c:a1e0::{host_id:x}")),
                status: NodeStatus::Online,
                tags: vec![format!("tag:team-{team}")],
                tag_source: NodeTagSource::Request,
                last_seen_unix_secs: Some(1_710_000_000 + host_id as u64),
            }
        })
        .collect()
}

pub fn sample_routes(nodes: &[Node]) -> Vec<Route> {
    nodes
        .iter()
        .step_by(3)
        .enumerate()
        .map(|(idx, node)| Route {
            id: (idx + 1) as u64,
            node_id: node.id,
            prefix: format!("10.{}.0.0/24", (idx % 200) + 1),
            advertised: true,
            approval: RouteApproval::Approved,
            approved_by_policy: idx % 2 == 0,
            is_exit_node: idx % 11 == 0,
        })
        .collect()
}

pub fn sample_early_noise() -> EarlyNoise {
    EarlyNoise {
        node_key_challenge: "nodekey:bench-challenge-00000000000000000000000000000000".to_string(),
    }
}

pub fn sample_map_response(peer_count: usize) -> MapResponse {
    let peers = (0..peer_count)
        .map(|idx| sample_control_node((idx + 2) as u64))
        .collect::<Vec<_>>();

    let user_profiles = (0..peer_count)
        .map(|idx| ControlUserProfile {
            id: (idx + 2) as u64,
            login_name: format!("user{idx}@example.com"),
            display_name: format!("User {idx}"),
            profile_pic_url: String::new(),
            groups: vec![format!("team-{}", idx % TEAM_COUNT)],
        })
        .collect();

    MapResponse {
        map_session_handle: "bench-session".to_string(),
        seq: 1,
        pop_browser_url: "https://control.example.com/device".to_string(),
        node: Some(sample_control_node(1)),
        derp_map: Some(sample_derp_map()),
        peers,
        dns_config: Some(ControlDnsConfig {
            resolvers: vec![
                ControlDnsResolver {
                    addr: "1.1.1.1".to_string(),
                },
                ControlDnsResolver {
                    addr: "8.8.8.8".to_string(),
                },
            ],
            domains: vec!["corp.internal".to_string()],
            proxied: true,
        }),
        domain: "corp.internal".to_string(),
        collect_services: Some(true),
        packet_filter: Some(sample_packet_filter()),
        packet_filters: Some(BTreeMap::from([(
            "base".to_string(),
            sample_packet_filter(),
        )])),
        user_profiles,
        health: Some(vec!["control plane healthy".to_string()]),
        display_messages: Some(BTreeMap::from([(
            "rotation".to_string(),
            Some(ControlDisplayMessage {
                title: "Rotate access keys".to_string(),
                text: "Quarterly rotation due in 3 days".to_string(),
                severity: ControlDisplayMessageSeverity::Medium,
                impacts_connectivity: false,
                primary_action: Some(ControlDisplayMessageAction {
                    label: "Open access".to_string(),
                    url: "https://control.example.com/access".to_string(),
                }),
            }),
        )])),
        client_version: Some(ControlClientVersion {
            running_latest: false,
            latest_version: "1.82.0".to_string(),
            urgent_security_update: false,
            notify: true,
            notify_url: "https://control.example.com/releases".to_string(),
            notify_text: "Upgrade available".to_string(),
        }),
        control_time: Some("2026-04-16T00:00:00Z".to_string()),
        ..MapResponse::default()
    }
}

pub fn mutated_map_response(base: &MapResponse) -> MapResponse {
    let mut current = base.clone();
    current.seq += 1;
    current.control_time = Some("2026-04-16T00:01:00Z".to_string());
    current.health = Some(vec!["policy update propagated".to_string()]);

    if let Some(node) = current.node.as_mut() {
        node.endpoints.push("100.64.0.1:41641".to_string());
        node.online = Some(true);
    }

    for (idx, peer) in current.peers.iter_mut().enumerate().step_by(5) {
        peer.endpoints.push(format!("192.0.2.{}:41641", idx + 10));
        peer.online = Some(idx % 2 == 0);
        peer.last_seen = format!("2026-04-16T00:{:02}:00Z", idx % 60);
    }

    current
        .peers
        .truncate(current.peers.len().saturating_sub(3));
    current
        .peers
        .push(sample_control_node((base.peers.len() + 10) as u64));

    current.display_messages = Some(BTreeMap::from([(
        "rotation".to_string(),
        Some(ControlDisplayMessage {
            title: "Rotation complete".to_string(),
            text: "Access material updated".to_string(),
            severity: ControlDisplayMessageSeverity::Low,
            impacts_connectivity: false,
            primary_action: None,
        }),
    )]));

    current
}

fn sample_control_node(id: u64) -> ControlNode {
    let octet = (id as usize % 250) + 1;
    let mut cap_map = BTreeMap::new();
    cap_map.insert(
        "https://tailscale.com/cap/file-sharing".to_string(),
        vec![json!({"enabled": true})],
    );

    ControlNode {
        id,
        stable_id: format!("stable-{id:04}"),
        name: format!("node-{id:04}"),
        user: (id % TEAM_COUNT as u64) + 1,
        key: format!("nodekey:{id:064x}"),
        key_expiry: "2026-10-01T00:00:00Z".to_string(),
        machine: format!("mkey:{:064x}", id + 1000),
        disco_key: format!("discokey:{:064x}", id + 2000),
        addresses: vec![format!("100.64.0.{octet}")],
        allowed_ips: vec![format!("100.64.0.{octet}/32")],
        endpoints: vec![format!("198.51.100.{octet}:41641")],
        legacy_derp_string: "127.3.3.40:900".to_string(),
        home_derp: 900,
        hostinfo: Some(json!({
            "Hostname": format!("node-{id:04}"),
            "OS": "linux",
            "NetInfo": {"PreferredDERP": 900}
        })),
        created: "2026-04-16T00:00:00Z".to_string(),
        cap: 120,
        tags: vec![format!("tag:team-{}", id as usize % TEAM_COUNT)],
        primary_routes: vec![format!("10.{}.0.0/24", (id % 200) + 1)],
        last_seen: "2026-04-16T00:00:00Z".to_string(),
        online: Some(true),
        machine_authorized: true,
        capabilities: vec!["https://tailscale.com/cap/is-admin".to_string()],
        cap_map,
        expired: false,
    }
}

fn sample_derp_map() -> ControlDerpMap {
    ControlDerpMap {
        home_params: None,
        regions: BTreeMap::from([(
            900,
            ControlDerpRegion {
                region_id: 900,
                region_code: "sha".to_string(),
                region_name: "Shanghai".to_string(),
                latitude: Some(31.2304),
                longitude: Some(121.4737),
                avoid: false,
                no_measure_no_home: false,
                nodes: vec![ControlDerpNode {
                    name: "sha-1".to_string(),
                    region_id: 900,
                    host_name: "derp.example.com".to_string(),
                    cert_name: "derp.example.com".to_string(),
                    ipv4: "203.0.113.10".to_string(),
                    ipv6: "2001:db8::10".to_string(),
                    stun_port: 3478,
                    stun_only: false,
                    derp_port: 443,
                    insecure_for_tests: false,
                    stun_test_ip: String::new(),
                    can_port80: false,
                }],
            },
        )]),
        omit_default_regions: false,
    }
}

fn sample_packet_filter() -> Vec<ControlFilterRule> {
    let mut filter = allow_all_packet_filter();
    filter.push(ControlFilterRule {
        src_ips: vec!["100.64.0.0/10".to_string()],
        dst_ports: vec![ControlNetPortRange {
            ip: "10.0.0.0/8".to_string(),
            ports: ControlPortRange {
                first: 22,
                last: 443,
            },
        }],
        ip_proto: vec![6, 17],
        cap_grant: Vec::new(),
    });
    filter
}

fn ipv4_for_index(host_id: usize) -> String {
    let third = ((host_id - 1) / 250) % 250;
    let fourth = ((host_id - 1) % 250) + 1;
    format!("100.64.{third}.{fourth}")
}
