use std::collections::BTreeMap;

use rscale::VERSION;
use rscale::domain::{
    AclPolicy, AutoApproverPolicy, Node, NodeStatus, NodeTagSource, PolicyRule, PolicySubject,
    Principal, Route, RouteApproval,
};

#[test]
fn public_policy_api_approves_request_tags_and_routes() -> Result<(), Box<dyn std::error::Error>> {
    let node = node_with_principal(1, "router", "100.64.0.10", 10, &[]);
    let principal = principal(10, "alice@example.com");
    let route = Route {
        id: 7,
        node_id: node.id,
        prefix: "10.10.0.0/24".to_string(),
        advertised: true,
        approval: RouteApproval::Pending,
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
        tag_owners: BTreeMap::from([("tag:router".to_string(), vec!["group:admins".to_string()])]),
        auto_approvers: AutoApproverPolicy {
            routes: BTreeMap::from([("10.0.0.0/8".to_string(), vec!["group:admins".to_string()])]),
            exit_node: Vec::new(),
        },
        ssh_rules: Vec::new(),
    };

    let approved_tags =
        policy.approved_request_tags(&node, Some(&principal), &["tag:router".to_string()])?;
    assert_eq!(approved_tags, vec!["tag:router".to_string()]);

    assert!(policy.auto_approves_route(&node, Some(&principal), &route)?);
    Ok(())
}

#[test]
fn public_policy_api_evaluates_visible_peers_and_packet_rules()
-> Result<(), Box<dyn std::error::Error>> {
    let client = node(1, "client", "100.64.0.10", &["tag:client"]);
    let server = node(2, "server", "100.64.0.20", &["tag:server"]);
    let route = Route {
        id: 10,
        node_id: server.id,
        prefix: "10.10.0.0/24".to_string(),
        advertised: true,
        approval: RouteApproval::Approved,
        approved_by_policy: false,
        is_exit_node: false,
    };
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

    let view = policy.evaluate_for_node(&server, &[client.clone(), server.clone()], &[route])?;

    assert!(view.visible_peer_ids.contains(&client.id));
    assert_eq!(view.packet_rules.len(), 1);
    assert_eq!(
        view.packet_rules[0].src_ips,
        vec![
            client
                .ipv4
                .clone()
                .ok_or_else(|| std::io::Error::other("missing ipv4 on integration test node"))?,
        ]
    );
    assert!(
        view.packet_rules[0]
            .destinations
            .iter()
            .any(|destination| destination.network == "100.64.0.20")
    );
    assert!(
        view.packet_rules[0]
            .destinations
            .iter()
            .any(|destination| destination.network == "10.10.0.0/24")
    );

    Ok(())
}

fn node(id: u64, hostname: &str, ipv4: &str, tags: &[&str]) -> Node {
    Node {
        id,
        stable_id: format!("stable-{VERSION}-{id}"),
        name: hostname.to_string(),
        hostname: hostname.to_string(),
        auth_key_id: None,
        principal_id: None,
        ipv4: Some(ipv4.to_string()),
        ipv6: None,
        status: NodeStatus::Online,
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        tag_source: if tags.is_empty() {
            NodeTagSource::None
        } else {
            NodeTagSource::Request
        },
        last_seen_unix_secs: Some(1_700_000_000),
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

fn principal(id: u64, login_name: &str) -> Principal {
    Principal {
        id,
        provider: "oidc".to_string(),
        issuer: Some("https://issuer.example.com".to_string()),
        subject: Some(format!("subject-{id}")),
        login_name: login_name.to_string(),
        display_name: "Alice".to_string(),
        email: Some(login_name.to_string()),
        groups: vec!["group:admins".to_string()],
        created_at_unix_secs: 1_700_000_000,
    }
}
