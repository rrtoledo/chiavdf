use chiavdf::{
    c_bindings::create_discriminant, constants::DISCRIMINANT_SIZE, hash::efficient_hash,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use std::time::{Duration, Instant};

pub fn bench_efficient_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hash");
    group.bench_function("Efficient", |b| {
        b.iter_custom(|n| {
            let mut rng = ChaCha20Rng::from_os_rng();

            // Create discriminant
            let mut seed_u32 = rng.next_u32();
            let seed = seed_u32.to_ne_bytes().to_vec();
            let mut disc = [0; DISCRIMINANT_SIZE / 8];
            create_discriminant(&seed, &mut disc);

            // Bench hash_to_class_group
            seed_u32 = rng.next_u32();
            let seed = seed_u32.to_ne_bytes().to_vec();
            let mut total_duration: Duration = Duration::ZERO;
            for _ in 0..n {
                let start = Instant::now();
                let _ = black_box(efficient_hash(&seed, &disc));
                total_duration = total_duration.saturating_add(start.elapsed());
            }
            total_duration
        })
    });
}

mod criterion_group {
    #![allow(missing_docs)]
    use super::{bench_efficient_hash, criterion_group, Criterion};

    criterion_group!(name = all;
                     config = Criterion::default();
                     targets =  bench_efficient_hash
    );
}

criterion_main!(criterion_group::all);
