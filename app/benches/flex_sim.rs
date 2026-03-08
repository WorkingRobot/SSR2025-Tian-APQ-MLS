use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
// use app::{solo, solo_pq_conf, hybrid_combiner, hybrid_combiner_flex};
use openmls::prelude::Ciphersuite;

/// Configuration for flexible benchmarking
#[derive(Debug, Clone)]
pub struct BenchConfig {
    pub clients: Vec<usize>,
    pub epochs: usize,
    pub sample_size: usize, // Criterion sampling parameter
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            clients: vec![2],
            epochs: 500,
            sample_size: 10,
        }
    }
}

/// Categorized ciphersuites for systematic testing
struct CiphersuiteCategories {
    traditional: Vec<Ciphersuite>,
    pq_conf: Vec<Ciphersuite>,      // PQ KEM + traditional signatures
    pq_conf_auth: Vec<Ciphersuite>, // PQ KEM + PQ signatures
    hybrid_combiner_conf: Vec<(Ciphersuite, Ciphersuite)>, // Combiner
    hybrid_combiner_conf_auth: Vec<(Ciphersuite, Ciphersuite)>, // Combiner
    hybrid: Vec<Ciphersuite>,
}

impl CiphersuiteCategories {
    fn new() -> Self {
        Self {
            traditional: vec![
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
                Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
                // Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521, // TODO: fix
                Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
            ],
            pq_conf: vec![
                // ML-KEM + traditional signatures
                Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519,
                Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_Ed25519,
                Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_Ed25519,
                Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed25519,
                Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_P256,
                Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_P256,
                Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_P384,
            ],
            pq_conf_auth: vec![
                // ML-KEM + ML-DSA (full post-quantum)
                Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_MLDSA44,
                Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65,
                Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
                Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
            ],
            hybrid_combiner_conf: vec![
                // // (PQ ciphersuite, Traditional ciphersuite) pairs
                // (
                //     Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_P256,
                //     Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                // ),
                // (
                //     Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_P256,
                //     Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                // ),
                // (
                //     Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_P384,
                //     Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
                // ),
                (
                    // Most direct comparison with X-Wing
                    Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_Ed25519,
                    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                ),
            ],
            hybrid_combiner_conf_auth: vec![
                // (PQ ciphersuite, Traditional ciphersuite) pairs
                (
                    Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_MLDSA44,
                    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                    //ECDSA-P256 is only EUF-CMA so we use a comparable DSA that's SUF-CMA instead
                    //(i.e. Ed25519)
                    //Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                ),
                (
                    Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
                    Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
                    //See note above on EUF vs SUF CMA
                    //Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
                ),
                (
                    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
                    Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448,
                    //See note above on EUF vs SUF CMA
                    //Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384
                ),
            ],
            hybrid: vec![
                // X-Wing (hybrid KEM)
                Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            ],
        }
    }
}

/// Benchmark traditional (classical) ciphersuites
fn bench_traditional(c: &mut Criterion, config: &BenchConfig) {
    let categories = CiphersuiteCategories::new();

    for ciphersuite in categories.traditional {
        let mut group = c.benchmark_group(format!("Traditional_{:?}", ciphersuite));
        group.sample_size(config.sample_size);

        for &client_count in &config.clients {
            group.bench_with_input(
                BenchmarkId::from_parameter(client_count),
                &client_count,
                |b, &size| {
                    b.iter(|| solo_with_epochs(black_box(size), ciphersuite, config.epochs));
                },
            );
        }
        group.finish();
    }
}

/// Benchmark PQ-Confidentiality ciphersuites (PQ KEM + classical signatures)
fn bench_pq_conf(c: &mut Criterion, config: &BenchConfig) {
    let categories = CiphersuiteCategories::new();

    for ciphersuite in categories.pq_conf {
        let mut group = c.benchmark_group(format!("PQ_Conf_{:?}", ciphersuite));
        group.sample_size(config.sample_size);

        for &client_count in &config.clients {
            group.bench_with_input(
                BenchmarkId::from_parameter(client_count),
                &client_count,
                |b, &size| {
                    b.iter(|| solo_with_epochs(black_box(size), ciphersuite, config.epochs));
                },
            );
        }
        group.finish();
    }
}

/// Benchmark PQ-Confidentiality+Authentication ciphersuites (PQ KEM + PQ signatures)
fn bench_pq_conf_auth(c: &mut Criterion, config: &BenchConfig) {
    let categories = CiphersuiteCategories::new();

    for ciphersuite in categories.pq_conf_auth {
        let mut group = c.benchmark_group(format!("PQ_Conf_Auth_{:?}", ciphersuite));
        group.sample_size(config.sample_size);

        for &client_count in &config.clients {
            group.bench_with_input(
                BenchmarkId::from_parameter(client_count),
                &client_count,
                |b, &size| {
                    b.iter(|| solo_with_epochs(black_box(size), ciphersuite, config.epochs));
                },
            );
        }
        group.finish();
    }
}

/// Benchmark hybrid ciphersuites
fn bench_hybrid_ciphersuites(c: &mut Criterion, config: &BenchConfig) {
    let categories = CiphersuiteCategories::new();

    for ciphersuite in categories.hybrid {
        let mut group = c.benchmark_group(format!("Hybrid_{:?}", ciphersuite));
        group.sample_size(config.sample_size);

        for &client_count in &config.clients {
            group.bench_with_input(
                BenchmarkId::from_parameter(client_count),
                &client_count,
                |b, &size| {
                    b.iter(|| solo_with_epochs(black_box(size), ciphersuite, config.epochs));
                },
            );
        }
        group.finish();
    }
}

/// Benchmark hybrid combiner with ciphersuite pairs across different ratios
fn bench_hybrid_combiner_conf_ratios(c: &mut Criterion, config: &BenchConfig) {
    // let ratios = vec![1, 10, 50, 100];
    let ratios = vec![1, 2, 5, 10, 50, 100];
    let categories = CiphersuiteCategories::new();

    // Iterate over each ciphersuite PAIR (tuple)
    for (cs_pq, cs_st) in categories.hybrid_combiner_conf {
        // Create a meaningful name for the benchmark group
        let group_name = format!(
            "Hybrid_Combiner_Conf_{:?}_with_{:?}",
            get_ciphersuite_short_name(cs_pq),
            get_ciphersuite_short_name(cs_st)
        );

        let mut group = c.benchmark_group(group_name);
        group.sample_size(config.sample_size);

        // Test each ratio for this ciphersuite pair
        for ratio in &ratios {
            for &client_count in &config.clients {
                group.bench_with_input(
                    BenchmarkId::new(
                        format!("ratio_{}_clients_{}", ratio, client_count),
                        client_count,
                    ),
                    &client_count,
                    |b, &size| {
                        b.iter(|| {
                            app::hybrid_combiner_flex(
                                // Changed from hybrid_combiner_flex_epochs
                                black_box(size as u8),
                                black_box(*ratio as u8),
                                black_box(config.epochs as i32), // epochs is now the 3rd parameter
                                cs_pq,
                                cs_st,
                            )
                        });
                    },
                );
            }
        }
        group.finish();
    }
}

fn bench_solo(c: &mut Criterion, config: &BenchConfig, ciphersuite: Ciphersuite) {
    let mut group = c.benchmark_group(format!("Solo_{:?}", ciphersuite));
    group.sample_size(config.sample_size);

    for &client_count in &config.clients {
        group.bench_with_input(
            BenchmarkId::from_parameter(client_count),
            &client_count,
            |b, &size| {
                b.iter(|| solo_with_epochs(black_box(size), ciphersuite, config.epochs));
            },
        );
    }
    group.finish();
}

fn bench_hybrid_ratio(c: &mut Criterion, config: &BenchConfig, ratio: usize, cs_pq: Ciphersuite, cs_st: Ciphersuite) {
    let group_name = format!(
        "Hybrid_Combiner_{:?}_with_{:?}",
        get_ciphersuite_short_name(cs_pq),
        get_ciphersuite_short_name(cs_st)
    );

    let mut group = c.benchmark_group(group_name);
    group.sample_size(config.sample_size);

    for &client_count in &config.clients {
        group.bench_with_input(
            BenchmarkId::new(
                format!("ratio_{}_clients_{}", ratio, client_count),
                client_count,
            ),
            &client_count,
            |b, &size| {
                b.iter(|| {
                    app::hybrid_combiner_flex(
                        // ADD THIS LINE - the function call was missing!
                        black_box(size as u8),
                        black_box(ratio as u8),
                        black_box(config.epochs as i32), // epochs is now the 3rd parameter
                        cs_pq,
                        cs_st,
                    )
                });
            },
        );
    }
    group.finish();
}

fn bench_hybrid(c: &mut Criterion, config: &BenchConfig, cs_pq: Ciphersuite, cs_st: Ciphersuite) {
    let ratios = vec![1, 10, 50, 100];

    let group_name = format!(
        "Hybrid_Combiner_{:?}_with_{:?}",
        get_ciphersuite_short_name(cs_pq),
        get_ciphersuite_short_name(cs_st)
    );

    let mut group = c.benchmark_group(group_name);
    group.sample_size(config.sample_size);

    for ratio in &ratios {
        for &client_count in &config.clients {
            group.bench_with_input(
                BenchmarkId::new(
                    format!("ratio_{}_clients_{}", ratio, client_count),
                    client_count,
                ),
                &client_count,
                |b, &size| {
                    b.iter(|| {
                        app::hybrid_combiner_flex(
                            // ADD THIS LINE - the function call was missing!
                            black_box(size as u8),
                            black_box(*ratio as u8),
                            black_box(config.epochs as i32), // epochs is now the 3rd parameter
                            cs_pq,
                            cs_st,
                        )
                    });
                },
            );
        }
    }
    group.finish();
}

/// Benchmark hybrid combiner with PQ conf+auth ciphersuite pairs across different ratios
fn bench_hybrid_combiner_conf_auth_ratios(c: &mut Criterion, config: &BenchConfig) {
    let ratios = vec![1, 10, 50, 100];
    let categories = CiphersuiteCategories::new();

    // Iterate over each ciphersuite PAIR (tuple) for conf+auth
    for (cs_pq, cs_st) in categories.hybrid_combiner_conf_auth {
        let group_name = format!(
            "Hybrid_Combiner_Conf_Auth_{:?}_with_{:?}",
            get_ciphersuite_short_name(cs_pq),
            get_ciphersuite_short_name(cs_st)
        );

        let mut group = c.benchmark_group(group_name);
        group.sample_size(config.sample_size);

        for ratio in &ratios {
            for &client_count in &config.clients {
                group.bench_with_input(
                    BenchmarkId::new(
                        format!("ratio_{}_clients_{}", ratio, client_count),
                        client_count,
                    ),
                    &client_count,
                    |b, &size| {
                        b.iter(|| {
                            app::hybrid_combiner_flex(
                                // ADD THIS LINE - the function call was missing!
                                black_box(size as u8),
                                black_box(*ratio as u8),
                                black_box(config.epochs as i32), // epochs is now the 3rd parameter
                                cs_pq,
                                cs_st,
                            )
                        });
                    },
                );
            }
        }
        group.finish();
    }
}

/// Helper function to get short names for ciphersuites (for cleaner benchmark names)
fn get_ciphersuite_short_name(cs: Ciphersuite) -> &'static str {
    match cs {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => "X25519_Ed25519",
        Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 => "X448_Ed448",
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256 => "P256_ECDSA",
        Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384 => "P384_ECDSA",
        Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521 => "P521_ECDSA",
        Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519 => "MLKEM512_Ed25519",
        Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_Ed25519 => "MLKEM768_Ed25519",
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed25519 => "MLKEM1024_Ed25519",
        Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_P256 => "MLKEM512_P256",
        Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_P256 => "MLKEM768_P256",
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_P384 => "MLKEM1024_P384",
        Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_MLDSA44 => "MLKEM512_MLDSA44",
        Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65 => "MLKEM768_MLDSA65",
        Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87 => "MLKEM1024_MLDSA87",
        Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 => "XWing_Ed25519",
        Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_Ed25519 => "MLKEM768_CHA_Ed25519",
        Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65 => "MLKEM768_CHA_MLDSA65",
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => "X25519_CHA_Ed25519",
        _ => unimplemented!(),
    }
}

fn cs_from_str(short_name: &str) -> Option<Ciphersuite> {
    match short_name {
        "X25519_Ed25519" => Some(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
        "X448_Ed448" => Some(Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448),
        "P256_ECDSA" => Some(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
        "P384_ECDSA" => Some(Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384),
        "P521_ECDSA" => Some(Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521),
        "MLKEM512_Ed25519" => Some(Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519),
        "MLKEM768_Ed25519" => Some(Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_Ed25519),
        "MLKEM1024_Ed25519" => Some(Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_Ed25519),
        "MLKEM512_P256" => Some(Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_P256),
        "MLKEM768_P256" => Some(Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_P256),
        "MLKEM1024_P384" => Some(Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_P384),
        "MLKEM512_MLDSA44" => Some(Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_MLDSA44),
        "MLKEM768_MLDSA65" => Some(Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65),
        "MLKEM1024_MLDSA87" => Some(Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87),
        "XWing_Ed25519" => Some(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519),
        "MLKEM768_CHA_Ed25519" => Some(Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_Ed25519),
        "MLKEM768_CHA_MLDSA65" => Some(Ciphersuite::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65),
        "X25519_CHA_Ed25519" => Some(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
        _ => None,
    }
}

/// Run one benchmark based on CLI arguments
#[cfg_attr(feature = "hotpath", hotpath::main)]
fn cli_args_benchmark(c: &mut Criterion) {
    use std::env;

    let client_count = env::var("FLEX_SIM_CLIENT_COUNT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(2);
    let epochs = env::var("FLEX_SIM_EPOCHS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(500);
    let sample_size = env::var("FLEX_SIM_SAMPLE_SIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(10);
    let cs1 = match env::var("FLEX_SIM_CS1").ok().and_then(|s| cs_from_str(&s)) {
        Some(cs) => cs,
        None => {
            // No ciphersuite specified — run quick benchmark instead
            println!("FLEX_SIM_CS1 not set, running quick benchmark");
            let config = BenchConfig {
                clients: vec![2],
                epochs: 5,
                sample_size: 10,
            };
            bench_solo(c, &config, Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
            return;
        }
    };
    let cs2 = env::var("FLEX_SIM_CS2")
        .ok()
        .and_then(|s| cs_from_str(&s));
    let ratio = env::var("FLEX_SIM_CS2_TO_CS1_RATIO")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);

    // Print out the values of the environment variables
    println!("Client count: {}", client_count);
    println!("Epochs: {}", epochs);
    println!("Sample size: {}", sample_size);
    println!("Primary ciphersuite: {:?}", cs1);
    if let Some(cs2) = cs2 {
        println!("Secondary ciphersuite: {:?}", cs2);
    } else {
        println!("Secondary ciphersuite: None");
    }

    // Configurable parameters
    let config = BenchConfig {
        clients: vec![client_count],
        epochs,
        sample_size,
    };

    println!("Running custom benchmark with config: {:?}", config);

    if let Some(cs2) = cs2 {
        bench_hybrid_ratio(c, &config, ratio, cs1, cs2);
    } else {
        bench_solo(c, &config, cs1);
    }
}

/// Comprehensive benchmark covering all categories
fn comprehensive_benchmark(c: &mut Criterion) {
    // Configurable parameters
    let config = BenchConfig {
        clients: vec![2],
        epochs: 500,
        sample_size: 10,
    };

    println!("Running comprehensive benchmark with config: {:?}", config);

    // Run all benchmark categories
    bench_traditional(c, &config);
    bench_pq_conf(c, &config);
    bench_pq_conf_auth(c, &config);
    bench_hybrid_ciphersuites(c, &config);

    // Add the new hybrid combiner benchmarks
    bench_hybrid_combiner_conf_ratios(c, &config);
    bench_hybrid_combiner_conf_auth_ratios(c, &config);
}

/// Combiner only benchmark
fn combiner_only_benchmark(c: &mut Criterion) {
    // Configurable parameters
    let config = BenchConfig {
        clients: vec![2],
        epochs: 500,
        sample_size: 10,
    };

    println!("Running combiner only benchmark with config: {:?}", config);

    // Add the new hybrid combiner benchmarks
    bench_hybrid_combiner_conf_ratios(c, &config);
    // bench_hybrid_combiner_conf_auth_ratios(c, &config);
}

/// Quick benchmark for development/testing
fn quick_benchmark(c: &mut Criterion) {
    let config = BenchConfig {
        clients: vec![2], // Small set for quick testing
        epochs: 5,        // Very few epochs for quick feedback
        sample_size: 10,  // Minimal sampling
    };

    println!("Running quick benchmark with config: {:?}", config);

    // Test one from each category
    let mut group = c.benchmark_group("Quick_Test");
    group.sample_size(config.sample_size);

    let test_cases = vec![
        (
            "Traditional",
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        ),
        (
            "PQ_Conf_MLKEM",
            Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_P256,
        ),
        (
            "PQ_Conf_Auth",
            Ciphersuite::MLS_192_MLKEM768_AES256GCM_SHA384_MLDSA65,
        ),
        (
            "Hybrid_XWing",
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
        ),
    ];

    for (name, ciphersuite) in test_cases {
        for &client_count in &config.clients {
            group.bench_function(&format!("{}_{}_clients", name, client_count), |b| {
                b.iter(|| solo_with_epochs(black_box(client_count), ciphersuite, config.epochs));
            });
        }
    }

    group.finish();
}

// Benchmark groups - choose which one to run
criterion_group!(combiner_only, combiner_only_benchmark);
criterion_group!(comprehensive, comprehensive_benchmark);
criterion_group!(quick, quick_benchmark);
criterion_group!(cli, cli_args_benchmark);

// Set FLEX_SIM_CS1 (and optionally FLEX_SIM_CS2, FLEX_SIM_CS2_TO_CS1_RATIO) env
// vars to control which benchmark runs. Without env vars, runs a quick default.
// Other groups: 'quick', 'comprehensive', 'combiner_only'
criterion_main!(cli);

fn solo_with_epochs(clients: usize, ciphersuite: Ciphersuite, epochs: usize) {
    app::solo_with_epochs(clients as u8, epochs as i32, ciphersuite);
}
