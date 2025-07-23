import secrets
import time

from chiavdf import create_discriminant, prove, verify_wesolowski


def test_prove_and_verify():
    discriminant_challenge = secrets.token_bytes(10)
    discriminant_size = 512
    discriminant = create_discriminant(discriminant_challenge, discriminant_size)
    
    # hard coded class group's element size in bqfc.h
    # if BQFC_MAX_D_BITS is changed, this value must be changed accordingly
    form_size = 388
    initial_el = b"\x08" + (b"\x00" * (form_size - 1))

    iters = 1_000_000
    t1 = time.time()
    result = prove(discriminant_challenge, initial_el, discriminant_size, iters, "")
    t2 = time.time()
    print(f"IPS: {iters / (t2 - t1)}")
    result_y = result[:form_size]
    proof = result[form_size : 2 * form_size]

    is_valid = verify_wesolowski(
        str(discriminant),
        initial_el,
        result_y,
        proof,
        iters,
    )
    assert is_valid

    # Creates another proof starting at the previous output
    iters_2 = 200_000
    t1 = time.time()
    result_2 = prove(discriminant_challenge, result_y, discriminant_size, iters_2, "")
    t2 = time.time()
    print(f"IPS: {iters_2 / (t2 - t1)}")

    is_valid = verify_wesolowski(
        str(discriminant),
        result_y,
        result_2[:form_size],
        result_2[form_size : 2 * form_size],
        iters_2,
    )
    assert is_valid


test_prove_and_verify()
