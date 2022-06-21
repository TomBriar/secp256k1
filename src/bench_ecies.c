/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdint.h>

#include "include/secp256k1_ecies.h"
#include "util.h"
#include "bench.h"

typedef struct {
    secp256k1_context* ctx;
} bench_ecies_data;

static void bench_ecies_setup(void* arg) {
    (void) arg;
}

static void bench_ecies(void* arg, int iters) {
    bench_ecies_data *data = (bench_ecies_data*)arg;

    (void) data;
    (void) iters;
}

int main(void) {
    bench_ecies_data data;
    int iters = get_iters(32);

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    run_benchmark("ecies_verify_bit", bench_ecies, bench_ecies_setup, NULL, &data, 10, iters);

    secp256k1_context_destroy(data.ctx);
    return 0;
}
