#include "c_wrapper.h"
#include <vector>
#include <gmpxx.h>
#include "../verifier.h"
#include "../prover_slow.h"
#include <cmath>


extern "C" {
    // C wrapper function
    bool create_discriminant_wrapper(const uint8_t* seed, size_t seed_size, size_t size_bits, uint8_t* result) {
        try {
            std::vector<uint8_t> seed_vector(seed, seed + seed_size);
            integer discriminant = CreateDiscriminant(seed_vector, size_bits);
            mpz_export(result, NULL, 1, 1, 0, 0, discriminant.impl);
            return true;
        } catch (...) {
            return false;
        }
    }

    // Evaluate x^2^T and compute a Wesolowski proof quickly
    // Return evaluation and proof bundled
    ByteArray prove_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, size_t form_size, uint64_t num_iterations) {
        try {
            integer discriminant;
            mpz_import(discriminant.impl, discriminant_size, 1, 1, 0, 0, discriminant_bytes);
            discriminant = - discriminant;

            form x = DeserializeForm(discriminant, x_s, form_size);

            std::vector<uint8_t> result = ProveSlow(discriminant, x, num_iterations, "");

            // Allocate memory for the result and copy data
            uint8_t* resultData = new uint8_t[result.size()];
            std::copy(result.begin(), result.end(), resultData);

            return ByteArray  { resultData, result.size() };
        } catch (...) {
            return ByteArray { nullptr, 0 };
        }
    }

    // Compute the evaluation x^2^T while storing found intermediate values
    // Return the evaluation and the intermediates values bundled
    ByteArray evaluate_to_prove_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, size_t form_size, uint64_t num_iterations) {
        try {
            integer discriminant;
            mpz_import(discriminant.impl, discriminant_size, 1, 1, 0, 0, discriminant_bytes);
            discriminant = - discriminant;

            form x = DeserializeForm(discriminant, x_s, form_size);

            std::vector<uint8_t> result = EvalSlow(discriminant, x, num_iterations, "");

            // Allocate memory for the result and copy data
            uint8_t* resultData = new uint8_t[result.size()];
            std::copy(result.begin(), result.end(), resultData);

            return ByteArray  { resultData, result.size() };
        } catch (...) {
            return ByteArray { nullptr, 0 };
        }
    }

    // Compute the Wesolowski proof quickly by giving intermediate values found when evaluating x to x^2^T
    // Return a Wesolowski proof
    ByteArray prove_int_only_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, const uint8_t* y_s, size_t form_size, const uint8_t* inter_s, size_t intermediate_size, uint64_t num_iterations) {
        try {
            integer discriminant;
            mpz_import(discriminant.impl, discriminant_size, 1, 1, 0, 0, discriminant_bytes);
            discriminant = - discriminant;

            form x = DeserializeForm(discriminant, x_s, form_size);
            form y = DeserializeForm(discriminant, y_s, form_size);
            assert(intermediate_size % form_size == 0);
            size_t nb_intermediate = intermediate_size / form_size;
            std::vector<form> intermediates;
            for (int i = 0; i < nb_intermediate; i++) {
                form in = DeserializeForm(discriminant, &inter_s[i*form_size], form_size);
                intermediates.push_back(in);
            }

            std::vector<uint8_t> result = ProveInter(discriminant,  x,  y, intermediates, num_iterations);

            // Allocate memory for the result and copy data
            uint8_t* resultData = new uint8_t[result.size()];
            std::copy(result.begin(), result.end(), resultData);

            return ByteArray  { resultData, result.size() };
        } catch (...) {
            return ByteArray { nullptr, 0 };
        }
    }

    // Compute the Wesolowski proof naively with a double and add method
    // Return a Wesolowski proof
    ByteArray prove_only_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, const uint8_t* y_s, size_t form_size,  uint64_t num_iterations) {
        try {
            PulmarkReducer reducer;

            integer discriminant;
            mpz_import(discriminant.impl, discriminant_size, 1, 1, 0, 0, discriminant_bytes);
            integer L=root(discriminant, 4);
            discriminant = - discriminant;
            
            form x = DeserializeForm(discriminant, x_s, form_size);
            form y = DeserializeForm(discriminant, y_s, form_size);

            // Computing prime l
            integer B = GetB(discriminant, x, y);

            // Computing 2^t/l
            integer power_iterations;
            integer one = integer(1);
            mpz_mul_2exp(power_iterations.impl, one.impl, num_iterations);
            mpz_fdiv_q(power_iterations.impl, power_iterations.impl, B.impl);

            // Computing proof x^floor((2^T) / l) using double and add method
            form res = FastPowFormNucomp(x, discriminant, power_iterations, L, reducer);
            std::vector<uint8_t> result = SerializeForm(res, discriminant.num_bits());

            // Allocate memory for the result and copy data
            uint8_t* resultData = new uint8_t[result.size()];
            std::copy(result.begin(), result.end(), resultData);

            return ByteArray  { resultData, result.size() };
        } catch (...) {
            return ByteArray { nullptr, 0 };
        }
    }

    // Verify a Wesolowski proof
    // Return true if valid, false otherwise
    bool verify_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, const uint8_t* y_s, const uint8_t* proof_s, size_t form_size, uint64_t num_iterations) {
        try {
           integer discriminant;
            mpz_import(discriminant.impl, discriminant_size, 1, 1, 0, 0, discriminant_bytes);
            discriminant = - discriminant;

            form x = DeserializeForm(discriminant, x_s, form_size);
            form y = DeserializeForm(discriminant, y_s, form_size);
            form proof = DeserializeForm(discriminant, proof_s, form_size);

            bool is_valid = false;
            VerifyWesolowskiProof(discriminant, x, y, proof, num_iterations, is_valid);

            return is_valid;
        } catch (...) {
            return false;
        }
    }

    // Verify a cascade of VDF evaluation and proofs
    bool verify_n_wesolowski_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, const uint8_t* proof_blob, size_t proof_blob_size, uint64_t num_iterations, uint64_t recursion) {
        try {
            integer discriminant;
            mpz_import(discriminant.impl, discriminant_size, 1, 1, 0, 0, discriminant_bytes);
            discriminant = - discriminant;

            return CheckProofOfTimeNWesolowski(
                discriminant,
                x_s,
                proof_blob,
                proof_blob_size,
                num_iterations,
                discriminant_size * 8,
                recursion
            );
        } catch (...) {
            return false;
        }
    }

    void delete_byte_array(ByteArray array) {
        delete[] array.data;
    }

    // Return form from  discriminant, a and b
    ByteArray from_ab(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* a_bytes, size_t a_size, const uint8_t* b_bytes, size_t b_size) {
        try {
            integer discriminant;
            mpz_import(discriminant.impl, discriminant_size, 1, 1, 0, 0, discriminant_bytes);
            discriminant = - discriminant;

            integer a;
            mpz_import(a.impl, a_size, 1, 1, 0, 0, a_bytes);

            integer b;
            mpz_import(b.impl, b_size, 1, 1, 0, 0, b_bytes);

            form x = form::from_abd(a,b, discriminant);

            std::vector<uint8_t> result = SerializeForm(x, discriminant.num_bits());

            // Allocate memory for the result and copy data
            uint8_t* resultData = new uint8_t[result.size()];
            std::copy(result.begin(), result.end(), resultData);

            return ByteArray  { resultData, result.size() };
        } catch (...) {
            return ByteArray { nullptr, 0 };
        }
    }

    // Return the class group identity element
    ByteArray identity_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size) {
        try {
            integer discriminant;
            mpz_import(discriminant.impl, discriminant_size, 1, 1, 0, 0, discriminant_bytes);
            discriminant = - discriminant;

            form identity = form::identity(discriminant);
            std::vector<uint8_t> result = SerializeForm(identity, discriminant.num_bits());

            // Allocate memory for the result and copy data
            uint8_t* resultData = new uint8_t[result.size()];
            std::copy(result.begin(), result.end(), resultData);


            return ByteArray  {resultData, result.size() };
        } catch (...) {
            return ByteArray { nullptr, 0 };
        }
    }

    // Return the class group generator
    ByteArray generator_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size) {
        try {
            integer discriminant;
            mpz_import(discriminant.impl, discriminant_size, 1, 1, 0, 0, discriminant_bytes);
            discriminant = - discriminant;

            form g = form::generator(discriminant);
            std::vector<uint8_t> result = SerializeForm(g, discriminant.num_bits());

            // Allocate memory for the result and copy data
            uint8_t* resultData = new uint8_t[result.size()];
            std::copy(result.begin(), result.end(), resultData);


            return ByteArray  {resultData, result.size() };
        } catch (...) {
            return ByteArray { nullptr, 0 };
        }
    }

    // Return x^power in a class group
    ByteArray power_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, size_t form_size, const uint8_t* power, size_t power_size) {
        try {
            integer discriminant;
            mpz_import(discriminant.impl, discriminant_size, 1, 1, 0, 0, discriminant_bytes);
            integer L=root(discriminant, 4);
            discriminant = - discriminant;

            form x = DeserializeForm(discriminant, x_s, form_size);

            integer p;
            mpz_import(p.impl, power_size, 1, 1, 0, 0, power);

            PulmarkReducer reducer;
            form y = FastPowFormNucomp(x, discriminant, p, L, reducer);

            std::vector<uint8_t> result = SerializeForm(y, discriminant.num_bits());

            // Allocate memory for the result and copy data
            uint8_t* resultData = new uint8_t[result.size()];
            std::copy(result.begin(), result.end(), resultData);

            return ByteArray  { resultData, result.size() };
        } catch (...) {
            return ByteArray { nullptr, 0 };
        }
    }

    // Return x⋅y in a class group
    ByteArray multiply_wrapper(const uint8_t* discriminant_bytes, size_t discriminant_size, const uint8_t* x_s, const uint8_t* y_s, size_t form_size) {
        try {
            integer discriminant;
            mpz_import(discriminant.impl, discriminant_size, 1, 1, 0, 0, discriminant_bytes);
            discriminant = - discriminant;

            form x = DeserializeForm(discriminant, x_s, form_size);
            form y = DeserializeForm(discriminant, y_s, form_size);

            form z = x * y;
            std::vector<uint8_t> result = SerializeForm(z, discriminant.num_bits());

            // Allocate memory for the result and copy data
            uint8_t* resultData = new uint8_t[result.size()];
            std::copy(result.begin(), result.end(), resultData);

            return ByteArray  { resultData, result.size() };
        } catch (...) {
            return ByteArray { nullptr, 0 };
        }
    }

    // Return a size_bits bit long integer as the output of SHA256(seed)
    bool hash_int_wrapper(const uint8_t* seed, size_t seed_size, size_t size_bits, uint8_t* result) {
        try {
            std::vector<uint8_t> seed_vector(seed, seed + seed_size);

            integer output = HashInt(seed_vector, size_bits);
            mpz_export(result, NULL, 1, 1, 0, 0, output.impl);
            return true;
        } catch (...) {
            return false;
        }
    }

    // Return a size_bits bit long prime number as the output of SHA256(seed)
    bool hash_prime_wrapper(const uint8_t* seed, size_t seed_size, size_t size_bits, uint8_t* result) {
        try {
            std::vector<uint8_t> seed_vector(seed, seed + seed_size);        

            integer output = HashPrime(seed_vector, size_bits, {int(size_bits)-1});
            mpz_export(result, NULL, 1, 1, 0, 0, output.impl);
            return true;
        } catch (...) {
            return false;
        }
    }
}
