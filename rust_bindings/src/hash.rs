use super::fastcrypto::hash::hash_to_class_group;

// Hash function from https://eprint.iacr.org/2024/295.pdf
// ``An Efficient Hash Function for Imaginary Class Groups" by Chalkias et al.
// Code taken and modified from https://github.com/MystenLabs/fastcrypto/blob/main/fastcrypto-vdf/src/class_group/hash.rs
pub fn efficient_hash(discriminant: &[u8], seed: &[u8]) -> Option<Vec<u8>> {
    hash_to_class_group(seed, discriminant)
}
