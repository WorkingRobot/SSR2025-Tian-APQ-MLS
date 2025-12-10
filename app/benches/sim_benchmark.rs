use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use app::{hybrid_combiner, solo, solo_pq, solo_st, solo_pq_conf};
use openmls::prelude::Ciphersuite;

/* pub fn criterion_benchmark(c: &mut Criterion) {
    //black_box input is the number of clients for the run
    c.bench_function("Full Simulation - Traditional - 2 users", |b| 
    b.iter(|| solo(black_box(2), Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)));

    /* c.bench_function("Full Simulation - Traditional - 2 users", |b| 
    b.iter(|| hybrid(black_box(2), black_box(100)))); */
} */

fn mass_benchmark(c: &mut Criterion) {
    let CS = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let mut group = c.benchmark_group("Traditional (AES)");
    group.sample_size(10);
    for size in [2,3,4,5,10,15,20,25,30,35,40,45,50,60,70,80,90,100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| solo(black_box(size), CS));
        });
    }
    group.finish();

    let CS = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    let mut group = c.benchmark_group("Traditional (ChaCha)");
    group.sample_size(10);
    for size in [2,3,4,5,10,15,20,25,30,35,40,45,50,60,70,80,90,100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| solo(black_box(size), CS));
        });
    }
    group.finish();


    let mut group = c.benchmark_group("Hybrid-100");
    group.sample_size(10);
    for size in [2,3,4,5,10,15,20,25,30,35,40,45,50,60,70,80,90,100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| hybrid_combiner(black_box(size), black_box(100)));
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Hybrid-50");
    group.sample_size(10);
    for size in [2,3,4,5,10,15,20,25,30,35,40,45,50,60,70,80,90,100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| hybrid_combiner(black_box(size), black_box(50)));
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Hybrid-10");
    group.sample_size(10);
    for size in [2,3,4,5,10,15,20,25,30,35,40,45,50,60,70,80,90,100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| hybrid_combiner(black_box(size), black_box(10)));
        });
    }
    group.finish();


    let CS = Ciphersuite::MLS_128_MLKEM512_AES128GCM_SHA256_Ed25519;
    let mut group = c.benchmark_group("PQ");
    group.sample_size(10);
    for size in [2,3,4,5,10,15,20,25,30,35,40,45,50,60,70,80,90,100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| solo(black_box(size), CS));
        });
    }
    group.finish();
}

// fn benchmark_ml_kem_768(c: &mut Criterion) {
//     let mut group = c.benchmark_group("MLS_Ciphersuites");
    
//     // Benchmark ML-KEM 768
//     group.bench_function("ML_KEM_768_3_clients", |b| {
//         b.iter(|| solo_pq_conf(black_box(3)))
//     });
    
//     group.bench_function("ML_KEM_768_5_clients", |b| {
//         b.iter(|| solo_pq_conf(black_box(5)))
//     });
   
//     group.bench_function("Standard_5_clients", |b| {
//         b.iter(|| solo_st(black_box(5)))
//     });
    
//     group.finish();
// }

criterion_group!(benches, mass_benchmark);
criterion_main!(benches);
