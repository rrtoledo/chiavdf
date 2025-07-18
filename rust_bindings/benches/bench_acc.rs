use chiavdf::{
    accumulators::{
        init_accumulators, init_seed, prove_accumulator, setup, update_accumulators,
        verify_accumulators,
    },
    bindings::{evaluate_and_prove, generator, power},
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use std::time::{Duration, Instant};

pub fn bench_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("Accumulator");
    group.bench_function("Setup", |b| {
        b.iter_custom(|n| {
            let mut rng = ChaCha20Rng::from_os_rng();
            let seed_u32 = rng.next_u32();
            let seed = seed_u32.to_ne_bytes().to_vec();

            let mut total_duration: Duration = Duration::ZERO;
            for _ in 0..n {
                let start = Instant::now();
                let _ = black_box(setup(&seed));
                total_duration = total_duration.saturating_add(start.elapsed());
            }
            total_duration
        })
    });
}

pub fn bench_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("Accumulator");
    group.bench_function("Update", |b| {
        b.iter_custom(|n| {
            let mut rng = ChaCha20Rng::from_os_rng();   
            let seed = rng.next_u32().to_ne_bytes().to_vec();
            let discriminant = &setup(&seed);
            let (acc_x, acc_y) = init_accumulators(discriminant);
            let default_el = generator(discriminant).unwrap();
            let seed_el = rng.next_u32() as u64;
            let x = power(discriminant, &default_el, &seed_el.to_be_bytes()).unwrap();
            let alpha = init_seed(&[x.clone()]);
            let (y, _pi) = evaluate_and_prove(discriminant, &x, 10).unwrap();

            let mut total_duration: Duration = Duration::ZERO;
            for _ in 0..n {
                let start = Instant::now();
                let _ = black_box(update_accumulators(
                    discriminant,
                    &acc_x,
                    &acc_y,
                    &x,
                    &y,
                    &alpha,
                ));
                total_duration = total_duration.saturating_add(start.elapsed());
            }
            total_duration
        })
    });
}

pub fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("Accumulator");

    let iterations = [1_000, 10_000];

    for num_iterations in iterations {
        let mut name: String = "Prove - ".to_string();
        name.push_str(num_iterations.to_string().as_str());
        group.bench_function(name, |b| {
            b.iter_custom(|n| {
                let mut rng = ChaCha20Rng::from_os_rng();
                let seed = rng.next_u32().to_ne_bytes().to_vec();
                let discriminant = &setup(&seed);
                let (acc_x, acc_y) = init_accumulators(discriminant);
                let default_el = generator(discriminant).unwrap();
                let seed_el = rng.next_u32() as u64;
                let x = power(discriminant, &default_el, &seed_el.to_be_bytes()).unwrap();
                let alpha = init_seed(&[x.clone()]);
                let (y, _pi) = evaluate_and_prove(discriminant, &x, 10).unwrap();
                let (accumulator_x, accumulator_y, _) =
                    update_accumulators(discriminant, &acc_x, &acc_y, &x, &y, &alpha);

                let mut total_duration: Duration = Duration::ZERO;
                for _ in 0..n {
                    let start = Instant::now();
                    let _ = black_box(prove_accumulator(
                        discriminant,
                        &accumulator_x,
                        &accumulator_y,
                        num_iterations,
                    ));
                    total_duration = total_duration.saturating_add(start.elapsed());
                }
                total_duration
            })
        });
    }
}

pub fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Accumulator");

    let iterations = [1_000, 10_000];

    for num_iterations in iterations {
        let mut name: String = "Verify - ".to_string();
        name.push_str(num_iterations.to_string().as_str());
        group.bench_function(name, |b| {
            b.iter_custom(|n| {
                let mut rng = ChaCha20Rng::from_os_rng();
                let seed = rng.next_u32().to_ne_bytes().to_vec();
                let discriminant = &setup(&seed);
                let (acc_x, acc_y) = init_accumulators(discriminant);
                let default_el = generator(discriminant).unwrap();
                let seed_el = rng.next_u32() as u64;
                let x = power(discriminant, &default_el, &seed_el.to_be_bytes()).unwrap();
                let alpha = init_seed(&[x.clone()]);
                let (y, _pi) = evaluate_and_prove(discriminant, &x, 10).unwrap();
                let (accumulator_x, accumulator_y, _) =
                    update_accumulators(discriminant, &acc_x, &acc_y, &x, &y, &alpha);
                let proof =
                    prove_accumulator(discriminant, &accumulator_x, &accumulator_y, num_iterations);

                let mut total_duration: Duration = Duration::ZERO;
                for _ in 0..n {
                    let start = Instant::now();
                    let _ = black_box(verify_accumulators(
                        discriminant,
                        &accumulator_x,
                        &accumulator_y,
                        &proof,
                        num_iterations,
                    ));
                    total_duration = total_duration.saturating_add(start.elapsed());
                }
                total_duration
            })
        });
    }
}

mod criterion_group {
    #![allow(missing_docs)]
    use super::{bench_prove, bench_setup, bench_update, bench_verify, criterion_group, Criterion};

    criterion_group!(name = all;
                     config = Criterion::default();
                     targets =  bench_setup, bench_update, bench_prove, bench_verify
    );
}

criterion_main!(criterion_group::all);
