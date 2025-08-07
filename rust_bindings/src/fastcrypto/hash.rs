// Adapted from https://github.com/MystenLabs/fastcrypto/commit/0acf0ff1a163c60e0dec1e16e4fbad4a4cf853bd

use crate::c_bindings;

use lazy_static::lazy_static;
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{FromPrimitive, One, Signed};
use std::ops::{Shl, Shr};

use sha2::{Digest, Sha256};

use num_prime::nt_funcs::is_prime;
use num_prime::PrimalityTestConfig;

use super::crt::solve_congruence_equation_system;
use super::jacobi;
use super::modular_sqrt::modular_square_root;

/// The security parameter for the hash function in bits. The image will be at least
/// 2^{2*SECURITY_PARAMETER} large to ensure that the hash function is collision resistant.
const SECURITY_PARAMETER_IN_BITS: u64 = 128;

/// This lower limit ensures that the default, secure parameters set below give valid results,
/// namely a reduced quadratic form.
const MINIMAL_DISCRIMINANT_SIZE: u64 = 600;

/// The image size of the hash function will be "Number of primes of size at most
/// DEFAULT_PRIME_FACTOR_SIZE_IN_BYTES" * DEFAULT_PRIME_FACTORS, so these have been set such that
/// the image is ~260 bits. See [n_bit_primes] for the details of this computation.
const DEFAULT_PRIME_FACTORS: u64 = 2;

/// The default size of the prime factors should be set such that it is not possible for an
/// adversary to precompute the VDF on all quadratic forms with the first coordinate being the
/// primes of this size. This is an issue because if an adversary can precompute (a1, _, _)^T and
/// (a2, _, _)^T then it is possible to compute (a1*a2, _, _)^T as the composition (a1, _, _)^T *
/// (a2, _, _)^T.
const DEFAULT_PRIME_FACTOR_SIZE_IN_BYTES: u64 = 20;

/// Check if the input is a probable prime.
///
/// We use the Baillie-PSW primality test here. This is in accordance with the recommendations of "Prime and
/// Prejudice: Primality Testing Under Adversarial Conditions" by Albrecht et al. (https://eprint.iacr.org/2018/749)
/// because this test is also used in use cases where an adversary could influence the input.
fn is_probable_prime(x: &BigUint) -> bool {
    is_prime(x, Some(PrimalityTestConfig::bpsw())).probably()
}

/// Generate a random quadratic form from a seed with the given discriminant. This method is
/// deterministic, and it is a random oracle on a large subset of the class group.
///
/// This method returns an [InvalidInput] error if the discriminant is so small that there are
/// no secure parameters, and it may also happen if the discriminant is not a prime.
pub fn hash_to_class_group(seed: &[u8], discriminant: &[u8]) -> Option<Vec<u8>> {
    if BigInt::from_bytes_be(Sign::Minus, discriminant).bits() <= MINIMAL_DISCRIMINANT_SIZE {
        return None;
    }
    hash_to_group_with_custom_parameters(seed, discriminant, DEFAULT_PRIME_FACTORS)
}

/// Generate a random quadratic form from a seed with the given discriminant and custom parameters.
///
/// The output will be a uniformly random element from the set of points (a,b,c) where a = p_1 ... p_k
/// for some primes p_i < 2^lambda.
///
/// If the discriminant is not a negative prime, an [InvalidInput] error may be returned.
///
/// The parameters must be chosen carefully to ensure that the function is secure and for all
/// use cases, [hash_to_group] should be used.
fn hash_to_group_with_custom_parameters(
    seed: &[u8],
    discriminant: &[u8],
    prime_factors: u64,
) -> Option<Vec<u8>> {
    //////// OLD updated checks
    // Ensure that the image is sufficiently large
    debug_assert!(
        prime_factors as f64 * n_bit_primes(DEFAULT_PRIME_FACTOR_SIZE_IN_BYTES * 8)
            >= SECURITY_PARAMETER_IN_BITS as f64
    );

    // Ensure that the prime factors are so large that the corresponding quadratic form cannot be precomputed.
    debug_assert!(
        n_bit_primes(DEFAULT_PRIME_FACTOR_SIZE_IN_BYTES * 8) >= SECURITY_PARAMETER_IN_BITS as f64
    );

    // Ensure that the result will be reduced
    let discriminant_bigint: BigInt = BigInt::from_bytes_be(Sign::Minus, discriminant);
    let sqrt_disc_over_2 = discriminant_bigint.abs().sqrt().shr(1);
    debug_assert!(
        sqrt_disc_over_2 > BigInt::one().shl(prime_factors * DEFAULT_PRIME_FACTOR_SIZE_IN_BYTES)
    );

    //////// NEW checks
    // k >= 1
    debug_assert!(prime_factors >= 1);

    // Discriminant = 1 (mod 4)
    debug_assert!(discriminant_bigint.clone() % BigInt::from_u8(4)? == BigInt::one());

    // We assume the discriminant is prime

    // p~(2^{2 SECURITY_PARAMETER_IN_BITS}) < sqrt(- Discriminant) / 2
    let (_lower, upper) = p_tilde_primes(1u64.shl(2 * SECURITY_PARAMETER_IN_BITS));
    debug_assert!(sqrt_disc_over_2 > BigInt::from_f64(upper.ceil()).unwrap());

    // Sample a and b such that a < sqrt(|discriminant|)/2 has exactly prime_factors prime factors and b is the square root of the discriminant modulo a.
    let (a, mut b) = sample_modulus(seed, discriminant, prime_factors)?;

    // b must be odd but may be negative
    if b.is_even() {
        b -= &a;
    }

    c_bindings::from_ab(discriminant, &a.to_bytes_be().1, &b.to_bytes_be().1)
}

/// Sample a product of `prime_factors` primes each of size `prime_factor_size_in_bytes` and return
/// this along with the square root of the discriminant modulo `a`. If the discriminant is not a
/// prime, an [InvalidInput] error may be returned.
fn sample_modulus(
    seed: &[u8],
    discriminant: &[u8],
    prime_factors: u64,
) -> Option<(BigInt, BigInt)> {
    // Seed a rng with the hash of the seed
    let mut rng = Sha256::digest(seed);
    let mut factors: Vec<BigInt> = Vec::with_capacity(prime_factors as usize);
    let mut square_roots: Vec<BigInt> = Vec::with_capacity(prime_factors as usize);

    let discriminant_bigint: BigInt = BigInt::from_bytes_be(Sign::Minus, discriminant);

    // Create a first factor of size lambda bits
    let mut big_factor_u8 = [0u8; SECURITY_PARAMETER_IN_BITS as usize / 8];
    let mut big_factor: BigInt;
    loop {
        assert!(c_bindings::hash_prime(&rng, &mut big_factor_u8));
        rng = Sha256::digest(rng);
        big_factor = BigInt::from_bytes_be(Sign::Plus, &big_factor_u8);

        // The primality check does not try divisions with small primes, so we do it here. This speeds up
        // the algorithm significantly.
        if PRIMES.iter().any(|p| big_factor.is_multiple_of(p)) {
            continue;
        }

        if jacobi::jacobi(&discriminant_bigint, &big_factor).expect("factor is odd and positive")
            == 1
            && is_probable_prime(factor.magnitude())
        {
            // Found a valid factor
            break;
        }
    }
    // This only fails if the discriminant is not prime.
    let big_square_root = modular_square_root(&discriminant_bigint, &big_factor, false).unwrap();
    factors.push(big_factor);
    square_roots.push(big_square_root);

    // Create small factors such that the total size of factors is 2*lambda
    for _ in 0..prime_factors {
        let mut factor_u8 = [0u8; DEFAULT_PRIME_FACTOR_SIZE_IN_BYTES as usize];
        let mut factor: BigInt;
        loop {
            assert!(c_bindings::hash_prime(&rng, &mut factor_u8));
            rng = Sha256::digest(rng);
            factor = BigInt::from_bytes_be(Sign::Plus, &factor_u8);

            if factors.contains(&factor) {
                continue;
            }

            // The primality check does not try divisions with small primes, so we do it here. This speeds up
            // the algorithm significantly.
            if PRIMES.iter().any(|p| factor.is_multiple_of(p)) {
                continue;
            }

            if jacobi::jacobi(&discriminant_bigint, &factor).expect("factor is odd and positive")
                == 1
                && is_probable_prime(factor.magnitude())
            {
                // Found a valid factor
                break;
            }
        }
        // This only fails if the discriminant is not prime.
        let square_root = modular_square_root(&discriminant_bigint, &factor, false).unwrap();
        factors.push(factor);
        square_roots.push(square_root);
    }

    let result = factors.iter().product();
    let square_root = solve_congruence_equation_system(&square_roots, &factors)
        .expect("The factors are distinct primes");

    Some((result, square_root))
}

/// Returns an approximation of the log2 of the number of primes smaller than 2^n.
fn n_bit_primes(n: u64) -> f64 {
    // The Prime Number Theorem states that the number of primes smaller than n is close to n / ln(n),
    // so the number of primes smaller than 2^n is approximately:
    //
    // log2(2^n / ln 2^n) = n - log2(ln 2^n)
    //                    = n - log2(n ln 2)
    //                    = n - log2(n) - log2(ln 2)
    let n_f64 = n as f64;
    n_f64 - n_f64.log2() - 2f64.ln().log2()
}

/// Returns a lower and upper bound on the number of prime smaller than n
fn p_tilde_primes(n: u64) -> (f64, f64) {
    // Compute the nth prime given the prime-counting theorem
    //
    // "An Efficient Hash Function" uses floor( n ln(n) ) < p~(n)
    // However, in Robin 83 (Estimation de la fonction de Tchebychef...)
    // gives a better approximation n(ln n + ln(ln(n)) - 1) < p~(n) for n > 2 and  p~(n)< n ln(n) + n ln(ln(n)) for n > 6
    assert!(n > 6);
    let n_f64 = n as f64;
    (
        n_f64 * (n_f64.ln() + n_f64.ln().ln() - 1.0),
        n_f64 * (n_f64.ln() + n_f64.ln().ln()),
    )
}

lazy_static! {
    /// The odd primes smaller than 100.
    pub static ref PRIMES: Vec<BigInt> = [
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97,
    ]
    .into_iter()
    .map(BigInt::from)
    .collect();
}
