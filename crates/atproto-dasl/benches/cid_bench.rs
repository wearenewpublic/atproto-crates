//! Benchmarks for CID computation and verification.

use atproto_dasl::cid::compute_cid;
use atproto_dasl::{compute_cid_blake3, compute_cid_for, verify_cid_bytes};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn make_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn bench_compute_cid(c: &mut Criterion) {
    let mut group = c.benchmark_group("compute_cid");

    for size in [64, 1024, 65536] {
        let data = make_data(size);

        group.bench_function(format!("sha256_{}b", size), |b| {
            b.iter(|| compute_cid(black_box(&data)));
        });

        group.bench_function(format!("blake3_{}b", size), |b| {
            b.iter(|| compute_cid_blake3(black_box(&data)));
        });
    }

    group.finish();
}

fn bench_compute_cid_for(c: &mut Criterion) {
    use serde::Serialize;

    #[derive(Serialize)]
    struct Post {
        #[serde(rename = "$type")]
        record_type: String,
        text: String,
    }

    let post = Post {
        record_type: "app.bsky.feed.post".into(),
        text: "Hello, Bluesky!".into(),
    };

    c.bench_function("compute_cid_for_struct", |b| {
        b.iter(|| compute_cid_for(black_box(&post)).unwrap());
    });
}

fn bench_verify_cid(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_cid");

    for size in [64, 1024, 65536] {
        let data = make_data(size);
        let cid_sha = compute_cid(&data);
        let cid_blake = compute_cid_blake3(&data);

        group.bench_function(format!("sha256_{}b", size), |b| {
            b.iter(|| verify_cid_bytes(black_box(&cid_sha), black_box(&data)).unwrap());
        });

        group.bench_function(format!("blake3_{}b", size), |b| {
            b.iter(|| verify_cid_bytes(black_box(&cid_blake), black_box(&data)).unwrap());
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_compute_cid,
    bench_compute_cid_for,
    bench_verify_cid
);
criterion_main!(benches);
