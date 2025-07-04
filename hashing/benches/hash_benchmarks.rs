//! Benchmarks for hashing operations

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::hint::black_box;
use cryypt_hashing::{Hash, on_result};
use tokio::runtime::Runtime;

// Test data sizes
const SMALL_DATA: &[u8] = b"Small test data";
const MEDIUM_DATA: &[u8] = &[0u8; 1024]; // 1KB
const LARGE_DATA: &[u8] = &[0u8; 1024 * 1024]; // 1MB

fn bench_sha256(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("SHA-256");
    
    for (name, data) in &[
        ("small", SMALL_DATA),
        ("medium", MEDIUM_DATA),
        ("large", LARGE_DATA),
    ] {
        group.bench_with_input(
            BenchmarkId::new("compute", name),
            data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        Hash::sha256()
                            .compute(black_box(*data))
                            .await
                            .unwrap()
                    })
                })
            },
        );
        
        // Benchmark with on_result handler
        group.bench_with_input(
            BenchmarkId::new("compute_with_handler", name),
            data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        Hash::sha256()
                            .on_result(on_result!(|result| {
                                Ok => Ok(result),
                                Err(e) => Err(e)
                            }))
                            .compute(black_box(*data))
                            .await
                            .unwrap()
                    })
                })
            },
        );
    }
    
    group.finish();
}

fn bench_sha3_256(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("SHA3-256");
    
    for (name, data) in &[
        ("small", SMALL_DATA),
        ("medium", MEDIUM_DATA),
        ("large", LARGE_DATA),
    ] {
        group.bench_with_input(
            BenchmarkId::new("compute", name),
            data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        Hash::sha3_256()
                            .compute(black_box(*data))
                            .await
                            .unwrap()
                    })
                })
            },
        );
    }
    
    group.finish();
}

fn bench_blake2b(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("BLAKE2b");
    
    for (name, data) in &[
        ("small", SMALL_DATA),
        ("medium", MEDIUM_DATA),
        ("large", LARGE_DATA),
    ] {
        group.bench_with_input(
            BenchmarkId::new("compute_64", name),
            data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        Hash::blake2b()
                            .compute(black_box(*data))
                            .await
                            .unwrap()
                    })
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("compute_32", name),
            data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        Hash::blake2b()
                            .with_output_size(32)
                            .compute(black_box(*data))
                            .await
                            .unwrap()
                    })
                })
            },
        );
    }
    
    group.finish();
}

fn bench_hmac(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("HMAC");
    let key = b"test_hmac_key";
    
    for (name, data) in &[
        ("small", SMALL_DATA),
        ("medium", MEDIUM_DATA),
        ("large", LARGE_DATA),
    ] {
        group.bench_with_input(
            BenchmarkId::new("sha256_hmac", name),
            data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        Hash::sha256()
                            .with_key(black_box(key))
                            .compute(black_box(*data))
                            .await
                            .unwrap()
                    })
                })
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("sha3_256_hmac", name),
            data,
            |b, data| {
                b.iter(|| {
                    rt.block_on(async {
                        Hash::sha3_256()
                            .with_key(black_box(key))
                            .compute(black_box(*data))
                            .await
                            .unwrap()
                    })
                })
            },
        );
    }
    
    group.finish();
}

fn bench_encoding(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("Encoding");
    
    // Create a hash result to benchmark encoding
    let hash_result = rt.block_on(async {
        Hash::sha256()
            .compute(b"test data")
            .await
            .unwrap()
    });
    
    group.bench_function("to_hex", |b| {
        b.iter(|| {
            black_box(hash_result.to_hex())
        })
    });
    
    group.bench_function("to_base64", |b| {
        b.iter(|| {
            black_box(hash_result.to_base64())
        })
    });
    
    group.bench_function("to_base64url", |b| {
        b.iter(|| {
            black_box(hash_result.to_base64url())
        })
    });
    
    group.finish();
}

fn bench_algorithm_comparison(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("Algorithm Comparison (1MB)");
    let data = LARGE_DATA;
    
    group.bench_function("SHA-256", |b| {
        b.iter(|| {
            rt.block_on(async {
                Hash::sha256()
                    .compute(black_box(data))
                    .await
                    .unwrap()
            })
        })
    });
    
    group.bench_function("SHA3-256", |b| {
        b.iter(|| {
            rt.block_on(async {
                Hash::sha3_256()
                    .compute(black_box(data))
                    .await
                    .unwrap()
            })
        })
    });
    
    group.bench_function("SHA3-384", |b| {
        b.iter(|| {
            rt.block_on(async {
                Hash::sha3_384()
                    .compute(black_box(data))
                    .await
                    .unwrap()
            })
        })
    });
    
    group.bench_function("SHA3-512", |b| {
        b.iter(|| {
            rt.block_on(async {
                Hash::sha3_512()
                    .compute(black_box(data))
                    .await
                    .unwrap()
            })
        })
    });
    
    group.bench_function("BLAKE2b-512", |b| {
        b.iter(|| {
            rt.block_on(async {
                Hash::blake2b()
                    .compute(black_box(data))
                    .await
                    .unwrap()
            })
        })
    });
    
    group.bench_function("BLAKE2b-256", |b| {
        b.iter(|| {
            rt.block_on(async {
                Hash::blake2b()
                    .with_output_size(32)
                    .compute(black_box(data))
                    .await
                    .unwrap()
            })
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_sha256,
    bench_sha3_256,
    bench_blake2b,
    bench_hmac,
    bench_encoding,
    bench_algorithm_comparison
);
criterion_main!(benches);