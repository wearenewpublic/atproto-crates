//! Criterion benchmarks comparing `XorSha256SetHash` vs `EcmhSetHash`.
//!
//! Phase 8 must answer
//! "is ECMH cheap enough that we can flip the workspace default?" These
//! benches drive that decision: add throughput, remove throughput, digest
//! size, and round-trip add+remove latency for both impls.
//!
//! Run with: `cargo bench -p atproto-space --features ecmh`

use atproto_space::set_hash::{SetHash, XorSha256SetHash};
use atproto_space::set_hash_ecmh::EcmhSetHash;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// Synthetic element bytes shaped like a record-element-bytes payload
/// (`<collection>/<rkey>:<cid>`) — typical Spaces SetHash input.
fn element(i: usize) -> Vec<u8> {
    format!("app.bsky.feed.post/3jui{i:08x}:bafyreihash{i:032x}").into_bytes()
}

fn bench_add_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("set_hash::add_throughput");

    for &n in &[1usize, 100, 1000] {
        let elements: Vec<Vec<u8>> = (0..n).map(element).collect();
        group.throughput(Throughput::Elements(n as u64));

        group.bench_with_input(BenchmarkId::new("xor_sha256", n), &elements, |b, els| {
            b.iter(|| {
                let mut h = XorSha256SetHash::empty();
                for e in els {
                    h.add(black_box(e));
                }
                black_box(h);
            });
        });

        group.bench_with_input(
            BenchmarkId::new("ecmh_secp256k1", n),
            &elements,
            |b, els| {
                b.iter(|| {
                    let mut h = EcmhSetHash::empty();
                    for e in els {
                        h.add(black_box(e));
                    }
                    black_box(h);
                });
            },
        );
    }

    group.finish();
}

fn bench_add_remove_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("set_hash::add_remove_round_trip");
    let e = element(42);

    group.bench_function("xor_sha256", |b| {
        let mut h = XorSha256SetHash::empty();
        b.iter(|| {
            h.add(black_box(&e));
            h.remove(black_box(&e));
        });
    });

    group.bench_function("ecmh_secp256k1", |b| {
        let mut h = EcmhSetHash::empty();
        b.iter(|| {
            h.add(black_box(&e));
            h.remove(black_box(&e));
        });
    });

    group.finish();
}

fn bench_digest_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("set_hash::digest_serialization");

    let mut xor = XorSha256SetHash::empty();
    let mut ecmh = EcmhSetHash::empty();
    for i in 0..100 {
        let e = element(i);
        xor.add(&e);
        ecmh.add(&e);
    }

    group.bench_function("xor_sha256.digest", |b| {
        b.iter(|| black_box(xor.digest()));
    });
    group.bench_function("xor_sha256.from_digest", |b| {
        let d = xor.digest();
        b.iter(|| black_box(XorSha256SetHash::from_digest(&d).unwrap()));
    });
    group.bench_function("ecmh_secp256k1.digest", |b| {
        b.iter(|| black_box(ecmh.digest()));
    });
    group.bench_function("ecmh_secp256k1.from_digest", |b| {
        let d = ecmh.digest();
        b.iter(|| black_box(EcmhSetHash::from_digest(&d).unwrap()));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_add_throughput,
    bench_add_remove_round_trip,
    bench_digest_serialization,
);
criterion_main!(benches);
