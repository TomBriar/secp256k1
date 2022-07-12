/***********************************************************************
 * Copyright (c) 2015 Pieter Wuille, Andrew Poelstra                   *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ECIES_BENCH_H
#define SECP256K1_MODULE_ECIES_BENCH_H

#include "../../../include/secp256k1_ecies.h"
#include "../../../include/secp256k1_ellswift.h"



typedef struct {
    secp256k1_context *ctx;
    unsigned char msg32[32];
    unsigned char rnd32[32];
    unsigned char ell64[64];
} bench_ecies_data;

static void bench_ecies_setup(void* arg) {
    unsigned char b_rnd32[32], b_ell_rnd32[32], b_ell64[64];
    int i;

    bench_ecies_data *data = (bench_ecies_data*)arg;

    for (i = 0; i < 32; i++) {
        b_ell_rnd32[i] = 1;
    }
    for (i = 0; i < 32; i++) {
        b_rnd32[i] = 1;
    }
    CHECK(secp256k1_ellswift_create(data->ctx, b_ell64, b_rnd32, b_ell_rnd32));
    
    for (i = 0; i < 32; i++) {
        data->msg32[i] = i+1;
    }
    for (i = 0; i < 32; i++) {
        data->rnd32[i] = i+2;
    }
    for (i = 0; i < 64; i++) {
        data->ell64[i] = b_ell64[i];
    }
 
}

static void bench_ecies_encrypt(void* arg, int iters) {
    unsigned char crypt[32], ell64[64];
    int i;

    bench_ecies_data *data = (bench_ecies_data*)arg;


    for (i = 0; i < iters; i++) {
        secp256k1_ecies_encrypt(data->ctx, crypt, ell64, data->msg32, 32, data->rnd32, data->ell64);
    }
}


void run_ecies_bench(int iters, int argc, char** argv) {
    bench_ecies_data data;
    int d = argc == 1;
    data.ctx = secp256k1_context_create(SECP256K1_FLAGS_TYPE_CONTEXT);

    if (d || have_flag(argc, argv, "ecies")) {
        run_benchmark("secp256k1_ecies_encrypt", bench_ecies_encrypt, bench_ecies_setup, NULL, &data, 10, iters);
    }
}

#endif /* SECP256K1_MODULE_AES_BENCH_H */
