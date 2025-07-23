import secrets
import time
from statistics import stdev
from tabulate import tabulate
import math

from chiavdf import (
    create_discriminant,
    prove_disc,
    evaluate_slow,
    prove_inter,
    verify_wesolowski,
    hash_int_both,
    hash_prime_both,
    evaluate,
)

def bench_prove_and_verify():
    # hard coded class group's element size in bqfc.h
    # if BQFC_MAX_D_BITS is changed, this value must be changed accordingly
    form_size = 388

    discriminant_challenge = secrets.token_bytes(10)

    discriminant_sizes = [4096]
    iterations = [10_000, 100_000, 1_000_000]
    benches = 100
    table = []
    table_prime = []
    table_alpha = []

    for d in discriminant_sizes:
        a_size = 128
        if d == 2048:
            a_size = 80
        elif d == 1024:
            a_size = 60
        elif d == 512:
            a_size = 40
        elif d == 256:
            a_size = 20
        for iters in iterations:
            res_prove = []
            res_verify = []

            time_eval = []
            time_eval_prove = []

            time_prime = []
            time_prime_eval = []

            time_alpha = []
            time_alpha_eval = []
            for b in range(benches):
                discriminant = create_discriminant(discriminant_challenge, d)
                initial_el = b"\x08" + (b"\x00" * (form_size - 1))

                t1 = time.time()
                result = prove_disc(discriminant, initial_el, iters, "")
                t2 = time.time()
                res_prove.append(t2 - t1)
                result_y = result[:form_size]
                proof = result[form_size : 2 * form_size]

                tv_1 = time.time()
                is_valid = verify_wesolowski(
                    str(discriminant),
                    initial_el,
                    result_y,
                    proof,
                    iters,
                )
                tv_2 = time.time()
                res_verify.append(tv_2 - tv_1)
                assert is_valid

                te1 = time.time()
                eval = evaluate_slow(discriminant, initial_el, iters, "")
                te2 = time.time()
                time_eval.append(te2 - te1)
                result_y_bis = eval[:form_size]
                inter = eval[form_size:]
                assert result_y == result_y_bis
                tp1 = time.time()
                proof = prove_inter(
                    discriminant, initial_el, result_y_bis, inter, iters
                )
                tp2 = time.time()
                time_eval_prove.append(tp2 - tp1)
                tpe1 = time.time()
                is_valid = verify_wesolowski(
                    str(discriminant),
                    initial_el,
                    result_y_bis,
                    proof,
                    iters,
                )
                tpe2 = time.time()
                res_verify.append(tpe2 - tpe1)
                assert is_valid

                tb_1 = time.time()
                p_str = hash_prime_both(discriminant, initial_el, result_y)[2:]
                p = int("0x" + p_str, 16)
                tb_2 = time.time()
                _ = evaluate(discriminant, initial_el, math.ceil(math.log(p, 2)), "")
                tb_3 = time.time()
                time_prime_eval.append(tb_3 - tb_2)
                time_prime.append(tb_2 - tb_1)

                tbi_1 = time.time()
                i_str = hash_int_both(discriminant, initial_el, result_y, a_size)[2:]
                i = int("0x" + i_str, 16)
                tbi_2 = time.time()
                _ = evaluate(discriminant, initial_el, 5, "")
                tbi_3 = time.time()

                tbi_2 = time.time()
                _ = evaluate(discriminant, initial_el, math.ceil(math.log(i, 2)), "")
                tbi_3 = time.time()
                time_alpha_eval.append(tbi_3 - tbi_2)
                time_alpha.append(tbi_2 - tbi_1)

            res_prove_mean = sum(res_prove) / len(res_prove)
            proveval_time = "{:.2E}".format(res_prove_mean)
            proveal_deviation = "{:.2E}".format(stdev(res_prove))

            eval_time_mean = sum(time_eval) / len(time_eval)
            eval_time = "{:.2E}".format(eval_time_mean) + " ({:}%)".format(
                math.ceil(100 * eval_time_mean / res_prove_mean)
            )
            eval_deviation = "{:.2E}".format(stdev(time_eval))

            prove_mean = sum(time_eval_prove) / len(time_eval_prove)
            proving_time = "{:.2E}".format(prove_mean) + " ({:}%)".format(
                math.ceil(100 * prove_mean / res_prove_mean)
            )
            proving_deviation = "{:.2E}".format(stdev(time_eval_prove))

            ips = "{:_.3f}".format(iters / (sum(time_eval) / len(time_eval)))

            vf_mean = sum(res_verify) / len(res_verify)
            verification_time = "{:.2E}".format(1000 * vf_mean) + " ({:}%)".format(
                math.ceil(100 * vf_mean / res_prove_mean)
            )
            verification_deviation = "{:.2E}".format(1000 * stdev(res_verify))

            table.append(
                [
                    d,
                    iters,
                    ips,
                    proveval_time,
                    proveal_deviation,
                    eval_time,
                    eval_deviation,
                    proving_time,
                    proving_deviation,
                    verification_time,
                    verification_deviation,
                ]
            )

            hash_time = "{:.2E}".format(sum(time_prime) / len(time_prime))
            hash_deviation = "{:.2E}".format(stdev(time_prime))
            eval_time = "{:.2E}".format(sum(time_prime_eval) / len(time_prime_eval))
            eval_deviation = "{:.2E}".format(stdev(time_prime_eval))
            table_prime.append(
                [d, hash_time, hash_deviation, eval_time, eval_deviation]
            )

            hash_alpha_time = "{:.2E}".format(sum(time_alpha) / len(time_alpha))
            hash_alpha_deviation = "{:.2E}".format(stdev(time_alpha))
            eval_alpha_time = "{:.2E}".format(
                sum(time_alpha_eval) / len(time_alpha_eval)
            )
            eval_alpha_deviation = "{:.2E}".format(stdev(time_alpha_eval))
            table_alpha.append(
                [
                    d,
                    hash_alpha_time,
                    hash_alpha_deviation,
                    eval_alpha_time,
                    eval_alpha_deviation,
                ]
            )
    headers = [
        "Size Discriminant",
        "#iters",
        "IPS",
        "EvalProve  (s)",
        "σ proving",
        "Eval (s)",
        "σ proving",
        "Prove (s)",
        "σ proving",
        "Verification (ms)",
        "σ verification",
    ]
    headers_eval = [
        "Size Discriminant",
        "Hash time (s)",
        "σ hashing",
        "Eval time (s)",
        "σ eval",
    ]
    print()
    print(tabulate(table, headers, tablefmt="orgtbl"))
    print()
    print("Exponentiate by prime")
    print(tabulate(table_prime, headers_eval, tablefmt="orgtbl"))
    print()
    print("Exponentiate by alpha")
    print(tabulate(table_alpha, headers_eval, tablefmt="orgtbl"))


bench_prove_and_verify()
