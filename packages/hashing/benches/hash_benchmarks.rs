//! Comprehensive benchmarks for hashing operations
//!
//! Implementation following TURD.md Phase 1 specifications with throughput
//! testing across multiple algorithms and data sizes.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use cryypt_hashing::api::Hash;
use tokio::runtime::Runtime;

/// Benchmark hash algorithms with different data sizes
fn benchmark_hash_algorithms(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("hash_throughput");

    // Test sizes: 1KB, 64KB, 1MB, 16MB - per TURD.md spec
    let sizes = [1024, 65536, 1_048_576, 16_777_216];

    for size in &sizes {
        group.throughput(Throughput::Bytes(*size as u64));

        let data = vec![0u8; *size];

        // Benchmark SHA256
        group.bench_with_input(BenchmarkId::new("SHA256", size), &data, |b, data| {
            b.iter(|| {
                rt.block_on(async {
                    let hash = Hash::sha256()
                        .compute(data.clone())
                        .await
                        .expect("SHA256 hash should succeed");
                    std::hint::black_box(hash);
                });
            });
        });

        // Benchmark BLAKE2b
        group.bench_with_input(BenchmarkId::new("BLAKE2b", size), &data, |b, data| {
            b.iter(|| {
                rt.block_on(async {
                    let hash = Hash::blake2b()
                        .compute(data.clone())
                        .await
                        .expect("BLAKE2b hash should succeed");
                    std::hint::black_box(hash);
                });
            });
        });
    }
    group.finish();
}

/// Benchmark builder pattern overhead
fn benchmark_builder_performance(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("builder_overhead");

    let data = vec![0u8; 1024]; // 1KB test data

    // Benchmark SHA256 builder creation and execution
    group.bench_function("SHA256_builder_creation", |b| {
        b.iter(|| {
            rt.block_on(async {
                let builder = Hash::sha256();
                let hash = builder
                    .compute(data.clone())
                    .await
                    .expect("Hash should succeed");
                std::hint::black_box(hash);
            });
        });
    });

    // Benchmark direct computation (baseline)
    group.bench_function("SHA256_direct_computation", |b| {
        b.iter(|| {
            rt.block_on(async {
                let hash = Hash::sha256()
                    .compute(data.clone())
                    .await
                    .expect("Hash should succeed");
                std::hint::black_box(hash);
            });
        });
    });

    group.finish();
}

/// Benchmark error handling performance
fn benchmark_error_handling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("error_handling");

    let valid_data = vec![0u8; 1024];

    // Benchmark successful operations (baseline)
    group.bench_function("successful_operation", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = Hash::sha256().compute(valid_data.clone()).await;
                let _ = std::hint::black_box(result);
            });
        });
    });

    // Benchmark with explicit error checking
    group.bench_function("with_error_checking", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = Hash::sha256().compute(valid_data.clone()).await;
                match result {
                    Ok(hash) => {
                        std::hint::black_box(hash);
                    }
                    Err(e) => {
                        std::hint::black_box(e);
                    }
                }
            });
        });
    });

    group.finish();
}

/// Benchmark memory allocation patterns
fn benchmark_memory_patterns(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("memory_patterns");

    // Test different allocation patterns
    let sizes = [256, 1024, 4096, 16384]; // Various buffer sizes

    for size in &sizes {
        // Benchmark with pre-allocated buffer
        group.bench_with_input(
            BenchmarkId::new("preallocated_buffer", size),
            size,
            |b, &size| {
                let data = vec![0u8; size]; // Pre-allocate outside benchmark
                b.iter(|| {
                    rt.block_on(async {
                        let hash = Hash::sha256()
                            .compute(data.clone())
                            .await
                            .expect("Hash should succeed");
                        std::hint::black_box(hash);
                    });
                });
            },
        );

        // Benchmark with allocation during operation
        group.bench_with_input(
            BenchmarkId::new("dynamic_allocation", size),
            size,
            |b, &size| {
                b.iter(|| {
                    rt.block_on(async {
                        let data = vec![0u8; size]; // Allocate inside benchmark
                        let hash = Hash::sha256()
                            .compute(data)
                            .await
                            .expect("Hash should succeed");
                        std::hint::black_box(hash);
                    });
                });
            },
        );
    }

    group.finish();
}

/// Benchmark algorithm comparison
fn benchmark_algorithm_comparison(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("algorithm_comparison");

    let data_1kb = vec![0u8; 1024];
    let data_64kb = vec![0u8; 65536];

    // Compare SHA256 vs BLAKE2b on 1KB
    group.bench_function("SHA256_1KB", |b| {
        b.iter(|| {
            rt.block_on(async {
                let hash = Hash::sha256()
                    .compute(data_1kb.clone())
                    .await
                    .expect("Hash should succeed");
                std::hint::black_box(hash);
            });
        });
    });

    group.bench_function("BLAKE2b_1KB", |b| {
        b.iter(|| {
            rt.block_on(async {
                let hash = Hash::blake2b()
                    .compute(data_1kb.clone())
                    .await
                    .expect("Hash should succeed");
                std::hint::black_box(hash);
            });
        });
    });

    // Compare SHA256 vs BLAKE2b on 64KB
    group.bench_function("SHA256_64KB", |b| {
        b.iter(|| {
            rt.block_on(async {
                let hash = Hash::sha256()
                    .compute(data_64kb.clone())
                    .await
                    .expect("Hash should succeed");
                std::hint::black_box(hash);
            });
        });
    });

    group.bench_function("BLAKE2b_64KB", |b| {
        b.iter(|| {
            rt.block_on(async {
                let hash = Hash::blake2b()
                    .compute(data_64kb.clone())
                    .await
                    .expect("Hash should succeed");
                std::hint::black_box(hash);
            });
        });
    });

    group.finish();
}

/// Benchmark concurrent operations
fn benchmark_concurrent_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("concurrent_operations");

    let data = vec![0u8; 1024]; // 1KB test data

    // Single threaded baseline
    group.bench_function("single_thread", |b| {
        b.iter(|| {
            rt.block_on(async {
                let hash = Hash::sha256()
                    .compute(data.clone())
                    .await
                    .expect("Hash should succeed");
                std::hint::black_box(hash);
            });
        });
    });

    // Multiple concurrent operations
    group.bench_function("concurrent_4_ops", |b| {
        b.iter(|| {
            rt.block_on(async {
                let tasks = (0..4)
                    .map(|_| Hash::sha256().compute(data.clone()))
                    .collect::<Vec<_>>();

                let results = futures::future::try_join_all(tasks)
                    .await
                    .expect("All hashes should succeed");
                std::hint::black_box(results);
            });
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_hash_algorithms,
    benchmark_builder_performance,
    benchmark_error_handling,
    benchmark_memory_patterns,
    benchmark_algorithm_comparison,
    benchmark_concurrent_operations
);
criterion_main!(benches);
