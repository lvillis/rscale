mod support;

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rscale::protocol::noise::{encode_json_body, encode_map_response_frame};
use support::{sample_early_noise, sample_map_response};

fn bench_early_noise_json(c: &mut Criterion) {
    let early_noise = sample_early_noise();

    c.bench_function("protocol/early_noise_json", |b| {
        b.iter(|| black_box(encode_json_body(black_box(&early_noise)).ok()))
    });
}

fn bench_protocol_frames(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol/frame_encoding");

    for &peer_count in &[32, 128, 512] {
        let response = sample_map_response(peer_count);

        group.throughput(Throughput::Elements(peer_count as u64));
        group.bench_with_input(
            BenchmarkId::new("map_plain", peer_count),
            &response,
            |b, response| {
                b.iter(|| black_box(encode_map_response_frame(black_box(response), "").ok()))
            },
        );
        group.bench_with_input(
            BenchmarkId::new("map_zstd", peer_count),
            &response,
            |b, response| {
                b.iter(|| black_box(encode_map_response_frame(black_box(response), "zstd").ok()))
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = support::criterion_config();
    targets = bench_early_noise_json, bench_protocol_frames
}
criterion_main!(benches);
