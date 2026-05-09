//! Benchmarks for DRISL (DAG-CBOR) encoding and decoding.

use atproto_dasl::{Ipld, from_slice, to_vec};
use criterion::{Criterion, criterion_group, criterion_main};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::hint::black_box;

#[derive(Serialize, Deserialize, Clone)]
struct Post {
    #[serde(rename = "$type")]
    record_type: String,
    text: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    langs: Vec<String>,
}

fn make_post() -> Post {
    Post {
        record_type: "app.bsky.feed.post".into(),
        text: "Hello, Bluesky! This is a test post with some content.".into(),
        created_at: "2024-01-01T00:00:00.000Z".into(),
        langs: vec!["en".into()],
    }
}

fn make_large_map() -> BTreeMap<String, i64> {
    (0..100)
        .map(|i| (format!("key_{:03}", i), i as i64))
        .collect()
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");

    group.bench_function("bool", |b| {
        b.iter(|| to_vec(black_box(&true)).unwrap());
    });

    group.bench_function("i64", |b| {
        b.iter(|| to_vec(black_box(&42i64)).unwrap());
    });

    group.bench_function("f64", |b| {
        b.iter(|| to_vec(black_box(&2.5_f64)).unwrap());
    });

    group.bench_function("string_short", |b| {
        b.iter(|| to_vec(black_box(&"hello")).unwrap());
    });

    group.bench_function("string_long", |b| {
        let s = "a".repeat(1000);
        b.iter(|| to_vec(black_box(&s)).unwrap());
    });

    let post = make_post();
    group.bench_function("struct_post", |b| {
        b.iter(|| to_vec(black_box(&post)).unwrap());
    });

    let map = make_large_map();
    group.bench_function("map_100_entries", |b| {
        b.iter(|| to_vec(black_box(&map)).unwrap());
    });

    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");

    let bool_bytes = to_vec(&true).unwrap();
    group.bench_function("bool", |b| {
        b.iter(|| from_slice::<bool>(black_box(&bool_bytes)).unwrap());
    });

    let i64_bytes = to_vec(&42i64).unwrap();
    group.bench_function("i64", |b| {
        b.iter(|| from_slice::<i64>(black_box(&i64_bytes)).unwrap());
    });

    let f64_bytes = to_vec(&2.5_f64).unwrap();
    group.bench_function("f64", |b| {
        b.iter(|| from_slice::<f64>(black_box(&f64_bytes)).unwrap());
    });

    let string_bytes = to_vec(&"hello").unwrap();
    group.bench_function("string_short", |b| {
        b.iter(|| from_slice::<String>(black_box(&string_bytes)).unwrap());
    });

    let long_string = "a".repeat(1000);
    let long_bytes = to_vec(&long_string).unwrap();
    group.bench_function("string_long", |b| {
        b.iter(|| from_slice::<String>(black_box(&long_bytes)).unwrap());
    });

    let post = make_post();
    let post_bytes = to_vec(&post).unwrap();
    group.bench_function("struct_post", |b| {
        b.iter(|| from_slice::<Post>(black_box(&post_bytes)).unwrap());
    });

    let map = make_large_map();
    let map_bytes = to_vec(&map).unwrap();
    group.bench_function("map_100_entries", |b| {
        b.iter(|| from_slice::<BTreeMap<String, i64>>(black_box(&map_bytes)).unwrap());
    });

    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    let post = make_post();
    group.bench_function("struct_post", |b| {
        b.iter(|| {
            let bytes = to_vec(black_box(&post)).unwrap();
            from_slice::<Post>(black_box(&bytes)).unwrap()
        });
    });

    let map = make_large_map();
    group.bench_function("map_100_entries", |b| {
        b.iter(|| {
            let bytes = to_vec(black_box(&map)).unwrap();
            from_slice::<BTreeMap<String, i64>>(black_box(&bytes)).unwrap()
        });
    });

    let post_bytes = to_vec(&post).unwrap();
    group.bench_function("ipld_struct_post", |b| {
        b.iter(|| {
            let ipld: Ipld = from_slice(black_box(&post_bytes)).unwrap();
            to_vec(black_box(&ipld)).unwrap()
        });
    });

    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode, bench_roundtrip);
criterion_main!(benches);
