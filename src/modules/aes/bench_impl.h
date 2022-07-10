/***********************************************************************
 * Copyright (c) 2015 Pieter Wuille, Andrew Poelstra                   *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_AES_BENCH_H
#define SECP256K1_MODULE_AES_BENCH_H

#include "../../../include/secp256k1_aes.h"

double gettimedouble(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_usec * 0.000001 + tv.tv_sec;
}

static void bench_AES128_init(void* data, int iters) {
    AES128_ctx* ctx = (AES128_ctx*)data;
    int i;
    for (i = 0; i < iters; i++) {
        AES128_init(ctx, (unsigned char*)ctx);
    }
}

static void bench_AES128_encrypt_setup(void* data) {
    AES128_ctx* ctx = (AES128_ctx*)data;
    static const unsigned char key[16] = {0};
    AES128_init(ctx, key);
}

static void bench_AES128_encrypt(void* data, int iters) {
    const AES128_ctx* ctx = (const AES128_ctx*)data;
    unsigned char scratch[16] = {0};
    int i;
    for (i = 0; i < iters / 16; i++) {
        AES128_encrypt(ctx, 1, scratch, scratch);
    }
}

static void bench_AES128_decrypt(void* data, int iters) {
    const AES128_ctx* ctx = (const AES128_ctx*)data;
    unsigned char scratch[16] = {0};
    int i;
    for (i = 0; i < iters / 16; i++) {
        AES128_decrypt(ctx, 1, scratch, scratch);
    }
}

static void bench_AES192_init(void* data, int iters) {
    AES192_ctx* ctx = (AES192_ctx*)data;
    int i;
    for (i = 0; i < iters; i++) {
        AES192_init(ctx, (unsigned char*)ctx);
    }
}

static void bench_AES192_encrypt_setup(void* data) {
    AES192_ctx* ctx = (AES192_ctx*)data;
    static const unsigned char key[24] = {0};
    AES192_init(ctx, key);
}

static void bench_AES192_encrypt(void* data, int iters) {
    const AES192_ctx* ctx = (const AES192_ctx*)data;
    unsigned char scratch[16] = {0};
    int i;
    for (i = 0; i < iters / 16; i++) {
        AES192_encrypt(ctx, 1, scratch, scratch);
    }
}

static void bench_AES192_decrypt(void* data, int iters) {
    const AES192_ctx* ctx = (const AES192_ctx*)data;
    unsigned char scratch[16] = {0};
    int i;
    for (i = 0; i < iters / 16; i++) {
        AES192_decrypt(ctx, 1, scratch, scratch);
    }
}

static void bench_AES256_init(void* data, int iters) {
    AES256_ctx* ctx = (AES256_ctx*)data;
    int i;
    for (i = 0; i < iters; i++) {
        AES256_init(ctx, (unsigned char*)ctx);
    }
}


static void bench_AES256_encrypt_setup(void* data) {
    AES256_ctx* ctx = (AES256_ctx*)data;
    static const unsigned char key[32] = {0};
    AES256_init(ctx, key);
}

static void bench_AES256_encrypt(void* data, int iters) {
    const AES256_ctx* ctx = (const AES256_ctx*)data;
    unsigned char scratch[16] = {0};
    int i;
    for (i = 0; i < iters / 16; i++) {
        AES256_encrypt(ctx, 1, scratch, scratch);
    }
}

static void bench_AES256_decrypt(void* data, int iters) {
    const AES256_ctx* ctx = (const AES256_ctx*)data;
    unsigned char scratch[16] = {0};
    int i;
    for (i = 0; i < iters / 16; i++) {
        AES256_decrypt(ctx, 1, scratch, scratch);
    }
}

void run_aes_bench(int iters, int argc, char** argv) {
    int d = argc == 1;
    
    AES128_ctx ctx128;
    AES192_ctx ctx192;
    AES256_ctx ctx256;
    
    if (d || have_flag(argc, argv, "aes")) {
        run_benchmark("aes128_init", bench_AES128_init, NULL, NULL, &ctx128, 20, iters);
        run_benchmark("aes128_encrypt_byte", bench_AES128_encrypt, bench_AES128_encrypt_setup, NULL, &ctx128, 20, iters*8);
        run_benchmark("aes128_decrypt_byte", bench_AES128_decrypt, bench_AES128_encrypt_setup, NULL, &ctx128, 20, iters*8);
        run_benchmark("aes192_init", bench_AES192_init, NULL, NULL, &ctx192, 20, iters);
        run_benchmark("aes192_encrypt_byte", bench_AES192_encrypt, bench_AES192_encrypt_setup, NULL, &ctx192, 20, iters*8);
        run_benchmark("aes192_decrypt_byte", bench_AES192_decrypt, bench_AES192_encrypt_setup, NULL, &ctx192, 20, iters*8);
        run_benchmark("aes256_init", bench_AES256_init, NULL, NULL, &ctx256, 20, iters);
        run_benchmark("aes256_encrypt_byte", bench_AES256_encrypt, bench_AES256_encrypt_setup, NULL, &ctx256, 20, iters*8);
        run_benchmark("aes256_decrypt_byte", bench_AES256_decrypt, bench_AES256_encrypt_setup, NULL, &ctx256, 20, iters*8);
    }
}

#endif /* SECP256K1_MODULE_AES_BENCH_H */
