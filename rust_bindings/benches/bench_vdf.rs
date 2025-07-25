use chiavdf::{
    c_bindings::{
        create_discriminant, evaluate_and_prove, evaluate_to_prove, generator, power, prove,
        prove_ext, verify,
    },
    constants::DISCRIMINANT_SIZE,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use std::time::{Duration, Instant};

pub fn bench_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("VDF");
    group.bench_function("CreateDiscriminant", |b| {
        b.iter_custom(|n| {
            let mut rng = ChaCha20Rng::from_os_rng();
            let seed_u32 = rng.next_u32();
            let seed = seed_u32.to_ne_bytes().to_vec();
            let mut disc = [0; DISCRIMINANT_SIZE / 8];

            let mut total_duration: Duration = Duration::ZERO;
            for _ in 0..n {
                let start = Instant::now();
                let _ = black_box(create_discriminant(&seed, &mut disc));
                total_duration = total_duration.saturating_add(start.elapsed());
            }
            total_duration
        })
    });
}

pub fn bench_evalprove(c: &mut Criterion) {
    let mut group = c.benchmark_group("VDF");

    let iterations = [1_000, 10_000];

    for num_iterations in iterations {
        let mut name: String = "EvalProve - ".to_string();
        name.push_str(num_iterations.to_string().as_str());
        group.bench_function(name, |b| {
            b.iter_custom(|n| {
                let mut rng = ChaCha20Rng::from_os_rng();
                let seed = rng.next_u32().to_ne_bytes().to_vec();
                let mut disc = [0; DISCRIMINANT_SIZE / 8];
                create_discriminant(&seed, &mut disc);

                let default_el = generator(&disc).unwrap();
                let seed_el = rng.next_u32() as u64;
                let x = power(&disc, &default_el, &seed_el.to_be_bytes()).unwrap();

                let mut total_duration: Duration = Duration::ZERO;
                for _ in 0..n {
                    let start = Instant::now();
                    let _ = black_box(evaluate_and_prove(&disc, &x, num_iterations));
                    total_duration = total_duration.saturating_add(start.elapsed());
                }
                total_duration
            })
        });
    }
}

pub fn bench_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("VDF");

    let iterations = [1_000, 10_000];

    for num_iterations in iterations {
        let mut name: String = "Eval - ".to_string();
        name.push_str(num_iterations.to_string().as_str());
        group.bench_function(name, |b| {
            b.iter_custom(|n| {
                let mut rng = ChaCha20Rng::from_os_rng();
                let seed = rng.next_u32().to_ne_bytes().to_vec();
                let mut disc = [0; DISCRIMINANT_SIZE / 8];
                create_discriminant(&seed, &mut disc);

                let default_el = generator(&disc).unwrap();
                let seed_el = rng.next_u32() as u64;
                let x = power(&disc, &default_el, &seed_el.to_be_bytes()).unwrap();

                let mut total_duration: Duration = Duration::ZERO;
                for _ in 0..n {
                    let start = Instant::now();
                    let _ = black_box(evaluate_to_prove(&disc, &x, num_iterations));
                    total_duration = total_duration.saturating_add(start.elapsed());
                }
                total_duration
            })
        });
    }
}

pub fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("VDF");

    let iterations = [1_000, 10_000];

    for num_iterations in iterations {
        let mut name: String = "Prove (inter.)- ".to_string();
        name.push_str(num_iterations.to_string().as_str());
        group.bench_function(name, |b| {
            b.iter_custom(|n| {
                let mut rng = ChaCha20Rng::from_os_rng();
                let seed = rng.next_u32().to_ne_bytes().to_vec();
                let mut disc = [0; DISCRIMINANT_SIZE / 8];
                create_discriminant(&seed, &mut disc);

                let default_el = generator(&disc).unwrap();
                let seed_el = rng.next_u32() as u64;
                let x = power(&disc, &default_el, &seed_el.to_be_bytes()).unwrap();
                let (y, intermediates) = evaluate_to_prove(&disc, &x, num_iterations).unwrap();

                let mut total_duration: Duration = Duration::ZERO;
                for _ in 0..n {
                    let start = Instant::now();
                    let _ = black_box(prove_ext(&disc, &x, &y, &intermediates, num_iterations));
                    total_duration = total_duration.saturating_add(start.elapsed());
                }
                total_duration
            })
        });
    }
}

pub fn bench_prove_slow(c: &mut Criterion) {
    let mut group = c.benchmark_group("VDF");

    let iterations = [1_000, 10_000];

    for num_iterations in iterations {
        let mut name: String = "Prove (no inter.) - ".to_string();
        name.push_str(num_iterations.to_string().as_str());
        group.bench_function(name, |b| {
            b.iter_custom(|n| {
                let mut rng = ChaCha20Rng::from_os_rng();
                let seed = rng.next_u32().to_ne_bytes().to_vec();
                let mut disc = [0; DISCRIMINANT_SIZE / 8];
                create_discriminant(&seed, &mut disc);

                let default_el = generator(&disc).unwrap();
                let seed_el = rng.next_u32() as u64;
                let x = power(&disc, &default_el, &seed_el.to_be_bytes()).unwrap();
                let (y, _) = evaluate_to_prove(&disc, &x, num_iterations).unwrap();

                let mut total_duration: Duration = Duration::ZERO;
                for _ in 0..n {
                    let start = Instant::now();
                    let _ = black_box(prove(&disc, &x, &y, num_iterations));
                    total_duration = total_duration.saturating_add(start.elapsed());
                }
                total_duration
            })
        });
    }
}

pub fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("VDF");

    let iterations = [1_000, 10_000];

    for num_iterations in iterations {
        let mut name: String = "Verify - ".to_string();
        name.push_str(num_iterations.to_string().as_str());
        group.bench_function(name, |b| {
            b.iter_custom(|n| {
                let mut rng = ChaCha20Rng::from_os_rng();
                let seed = rng.next_u32().to_ne_bytes().to_vec();
                let mut disc = [0; DISCRIMINANT_SIZE / 8];
                create_discriminant(&seed, &mut disc);

                let default_el = generator(&disc).unwrap();
                let seed_el = rng.next_u32() as u64;
                let x = power(&disc, &default_el, &seed_el.to_be_bytes()).unwrap();
                let (y, pi) = evaluate_and_prove(&disc, &x, num_iterations).unwrap();

                let mut total_duration: Duration = Duration::ZERO;
                for _ in 0..n {
                    let start = Instant::now();
                    let _ = black_box(verify(&disc, &x, &y, &pi, num_iterations));
                    total_duration = total_duration.saturating_add(start.elapsed());
                }
                total_duration
            })
        });
    }
}

mod criterion_group {
    #![allow(missing_docs)]
    use super::{
        bench_eval, bench_evalprove, bench_prove, bench_prove_slow, bench_setup, bench_verify,
        criterion_group, Criterion,
    };

    criterion_group!(name = all;
                     config = Criterion::default();
                     targets = bench_setup, bench_evalprove, bench_eval, bench_prove, bench_prove_slow, bench_verify
    );
}

criterion_main!(criterion_group::all);
