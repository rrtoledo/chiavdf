use sha2::{Digest, Sha256};

use super::bindings;
use super::constants::DISCRIMINANT_SIZE;

pub fn setup(seed: &[u8]) -> Vec<u8> {
    let mut disc = [0; DISCRIMINANT_SIZE / 8];
    assert!(bindings::create_discriminant(seed, &mut disc));
    return disc.to_vec();
}

pub fn init_accumulators(discriminant: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let acc = bindings::identity(discriminant).unwrap();
    return (acc.clone(), acc);
}

pub fn init_seed(xs: &[Vec<u8>]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    xs.iter().for_each(|xi| hasher.update(xi));
    let seed = hasher.finalize().to_vec();
    return seed;
}

pub fn update_accumulators(
    discriminant: &[u8],
    acc_x: &[u8],
    acc_y: &[u8],
    x_i: &[u8],
    y_i: &[u8],
    seed: &[u8],
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(y_i);
    let exponent_seed = &hasher.finalize();
    let mut exponent = [0u8; 128 / 8];
    let success = bindings::hash_int(exponent_seed, &mut exponent);
    assert!(success);

    let x_raised = bindings::power(discriminant, x_i, &exponent).unwrap();
    let updated_acc_x = bindings::multiply(discriminant, acc_x, &x_raised).unwrap();

    let y_raised = bindings::power(discriminant, y_i, &exponent).unwrap();
    let updated_acc_y = bindings::multiply(discriminant, acc_y, &y_raised).unwrap();

    return (
        updated_acc_x.to_vec(),
        updated_acc_y.to_vec(),
        exponent_seed.to_vec(),
    );
}

pub fn prove_accumulator(
    discriminant: &[u8],
    accumulator_x: &[u8],
    accumulator_y: &[u8],
    num_iterations: u64,
) -> Vec<u8> {
    bindings::prove(discriminant, accumulator_x, accumulator_y, num_iterations).unwrap()
}

pub fn verify_accumulators(
    discriminant: &[u8],
    accumulator_x: &[u8],
    accumulator_y: &[u8],
    proof: &[u8],
    num_iterations: u64,
) -> bool {
    bindings::verify(
        discriminant,
        accumulator_x,
        accumulator_y,
        proof,
        num_iterations,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    #[test]
    fn test_accumulator() {
        let num_iterations: u64 = 1_000;

        let discriminant = &setup(b"HelloWorld");

        // Initializing accumulators
        let (acc_x, acc_y) = init_accumulators(discriminant);

        // Computing all elements
        let mut xs: Vec<Vec<u8>> = Vec::with_capacity(10);
        let default_el = bindings::generator(discriminant).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        for _i in 0..10 {
            // Create new element
            // TODO use hash_to_class_group
            let seed_i = rng.next_u32() as u64;
            let x_i = bindings::power(discriminant, &default_el, &seed_i.to_be_bytes()).unwrap();
            xs.push(x_i);
        }

        // Computing the initial seed
        let alpha = init_seed(&xs);

        // For each interval
        let (accumulator_x, accumulator_y, _) =
            xs.iter().fold((acc_x, acc_y, alpha), |acc, x_i| {
                // Retrieve accumulator state and latest seed
                let (xx, yy, seed) = acc;

                // Compute the VDF evaluation and proof
                let (y_i, pi_i) =
                    bindings::evaluate_and_prove(discriminant, x_i, num_iterations).unwrap();

                assert!(bindings::verify(
                    discriminant,
                    &x_i,
                    &y_i,
                    &pi_i,
                    num_iterations
                ));

                // Update the accumulators
                let res = update_accumulators(discriminant, &xx, &yy, &x_i, &y_i, &seed);
                res
            });

        // Compute final proof
        let pi = prove_accumulator(discriminant, &accumulator_x, &accumulator_y, num_iterations);

        assert!(verify_accumulators(
            discriminant,
            &accumulator_x,
            &accumulator_y,
            &pi,
            num_iterations
        ));
    }
}
