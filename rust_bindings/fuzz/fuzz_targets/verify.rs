#![no_main]

use chiavdf::{create_discriminant, evaluate_and_prove, verify_n_wesolowski};
use libfuzzer_sys::{arbitrary::Unstructured, fuzz_target};

pub const DISCRIMINANT_SIZE: usize = 4_096;
pub const FORM_SIZE: usize = 388;

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let genesis_challenge: [u8; 32] = unstructured.arbitrary().unwrap();
    let mut disc = [0; DISCRIMINANT_SIZE / 8];
    if !create_discriminant(&genesis_challenge, &mut disc) {
        return;
    };

    let mut default_el = [0; FORM_SIZE];
    default_el[0] = 0x08;
    let (result, proof) = evaluate_and_prove(&disc, &default_el, 231).unwrap();
    let valid = verify_n_wesolowski(&disc, &default_el, &proof, 231, 0);
    assert!(valid);
});
