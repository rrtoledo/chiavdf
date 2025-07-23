#![no_main]

use chiavdf::{create_discriminant, verify_n_wesolowski};
use libfuzzer_sys::{arbitrary::Unstructured, fuzz_target};

pub const DISCRIMINANT_SIZE: usize = 4_096;
pub const FORM_SIZE: usize = 388;

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let seed: [u8; 10] = unstructured.arbitrary().unwrap();
    let mut disc = [0; DISCRIMINANT_SIZE / 8];
    if !create_discriminant(&seed, &mut disc) {
        return;
    };
    let element: [u8; FORM_SIZE] = unstructured.arbitrary().unwrap();
    let proof: Vec<u8> = unstructured.arbitrary().unwrap();
    let iters: u8 = unstructured.arbitrary().unwrap();
    verify_n_wesolowski(&disc, &element, &proof, iters as u64, 0);
});
