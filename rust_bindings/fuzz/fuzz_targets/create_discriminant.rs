#![no_main]

use chiavdf::c_bindings::create_discriminant;
use libfuzzer_sys::{arbitrary::Unstructured, fuzz_target};

pub const DISCRIMINANT_SIZE: usize = 4_096;

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let seed: [u8; 10] = unstructured.arbitrary().unwrap();
    let mut disc = [0; DISCRIMINANT_SIZE / 8];
    assert!(create_discriminant(&seed, &mut disc));
});
