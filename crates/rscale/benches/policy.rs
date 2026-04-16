mod support;

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use support::{sample_nodes, sample_policy, sample_routes};

fn bench_policy_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy/evaluate_for_node");

    for &(node_count, rule_count) in &[(32, 16), (128, 64), (512, 128)] {
        let nodes = sample_nodes(node_count);
        let routes = sample_routes(&nodes);
        let policy = sample_policy(rule_count);
        let Some(subject) = nodes
            .iter()
            .find(|node| node.tags.iter().any(|tag| tag == "tag:team-1"))
            .cloned()
        else {
            return;
        };

        group.throughput(Throughput::Elements(node_count as u64));
        group.bench_with_input(
            BenchmarkId::new("acl+grants", format!("{node_count}-nodes")),
            &(policy, subject, nodes, routes),
            |b, (policy, subject, nodes, routes)| {
                b.iter(|| {
                    black_box(
                        policy
                            .evaluate_for_node(
                                black_box(subject),
                                black_box(nodes.as_slice()),
                                black_box(routes.as_slice()),
                            )
                            .ok(),
                    )
                });
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = support::criterion_config();
    targets = bench_policy_evaluate
}
criterion_main!(benches);
