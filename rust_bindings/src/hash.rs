// Adapted from https://github.com/MystenLabs/fastcrypto/commit/0acf0ff1a163c60e0dec1e16e4fbad4a4cf853bd

use crate::bindings;

pub fn hash_to_class_group(discriminant: &[u8], _seed: &[u8]) -> Option<Vec<u8>> {
    //TODO
    let gen = bindings::generator(discriminant)?;
    Some(gen)
}
