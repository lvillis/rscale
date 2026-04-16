mod support;

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rscale::protocol::{encode_map_response_frame, incremental_map_response, response_signature};
use support::{mutated_map_response, sample_map_response};

fn bench_incremental_map_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("map_response/incremental");

    for &peer_count in &[32, 128, 512] {
        let previous = sample_map_response(peer_count);
        let current = mutated_map_response(&previous);

        group.throughput(Throughput::Elements(peer_count as u64));
        group.bench_with_input(
            BenchmarkId::new("delta", peer_count),
            &(previous, current),
            |b, (previous, current)| {
                b.iter(|| {
                    black_box(incremental_map_response(
                        black_box(previous),
                        black_box(current),
                    ))
                });
            },
        );
    }

    group.finish();
}

fn bench_map_response_signature(c: &mut Criterion) {
    let mut group = c.benchmark_group("map_response/signature");

    for &peer_count in &[32, 128, 512] {
        let response = sample_map_response(peer_count);

        group.throughput(Throughput::Elements(peer_count as u64));
        group.bench_with_input(
            BenchmarkId::new("response_signature", peer_count),
            &response,
            |b, response| b.iter(|| black_box(response_signature(black_box(response)).ok())),
        );
    }

    group.finish();
}

fn bench_map_response_frame_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("map_response/frame_encoding");

    for &peer_count in &[32, 128, 512] {
        let response = sample_map_response(peer_count);

        group.throughput(Throughput::Elements(peer_count as u64));
        group.bench_with_input(
            BenchmarkId::new("plain", peer_count),
            &response,
            |b, response| {
                b.iter(|| black_box(encode_map_response_frame(black_box(response), "").ok()))
            },
        );
        group.bench_with_input(
            BenchmarkId::new("zstd", peer_count),
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
    targets =
        bench_incremental_map_response,
        bench_map_response_signature,
        bench_map_response_frame_encoding
}
criterion_main!(benches);
