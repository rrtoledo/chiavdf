#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <string>

#ifdef __cplusplus
#include <cstddef> // for size_t
#include <cstdint> // for uint8_t
extern "C" {
#endif

bool create_discriminant_wrapper(const uint8_t* seed, size_t seed_size, size_t size_bits, uint8_t* result);

// Define a struct to hold the byte array and its length
typedef struct {
    uint8_t* data;
    size_t length;
} ByteArray;
ByteArray prove_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, size_t x_s_size, uint64_t num_iterations);
ByteArray evaluate_to_prove_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, size_t x_s_size, uint64_t num_iterations);
ByteArray prove_only_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, const uint8_t* y_s, size_t form_size, uint64_t num_iterations);
ByteArray prove_int_only_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, const uint8_t* y_s, size_t form_size, const uint8_t* inter_s, size_t intermediate_size, uint64_t num_iterations);
bool verify_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, const uint8_t* y_s, const uint8_t* proof_s, size_t form_size, uint64_t num_iterations);
bool verify_n_wesolowski_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, const uint8_t* proof_blob, size_t proof_blob_size, uint64_t num_iterations, uint64_t recursion);
void delete_byte_array(ByteArray array);

ByteArray from_ab(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* a_bytes, size_t a_size, const uint8_t* b_bytes, size_t b_size);
ByteArray identity_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size);
ByteArray generator_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size);
ByteArray power_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, size_t form_size, const uint8_t* power, size_t power_size);
ByteArray multiply_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, const uint8_t* y_s, size_t form_size);

bool hash_int_wrapper(const uint8_t* seed, size_t seed_size, size_t size_bits, uint8_t* result);
bool hash_prime_wrapper(const uint8_t* seed, size_t seed_size, size_t size_bits, uint8_t* result);
#ifdef __cplusplus
}
#endif
