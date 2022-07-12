/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_ECIES_MAIN_H
#define _SECP256K1_MODULE_ECIES_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_ecies.h"
#include "../../../include/secp256k1_ellswift.h"
#include "../../../include/secp256k1_aes.h"
#include "math.h"



int secp256k1_ecies_encrypt(const secp256k1_context* ctx, unsigned char *crypt, unsigned char *a_ell64, const unsigned char *plain, const size_t size, const unsigned char *rnd32, const unsigned char *b_ell64) {
	secp256k1_pubkey b_p;
    secp256k1_ge b_g;
    AES256_CBC_ctx aes_ctx;
    secp256k1_sha256 hash;
    
    unsigned char symetric_key[32], rnd32_2[32];
    
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(plain != NULL);
    ARG_CHECK(rnd32 != NULL);
    ARG_CHECK(b_ell64 != NULL);

    secp256k1_ellswift_decode(ctx, &b_p, b_ell64);

    if (secp256k1_pubkey_load(ctx, &b_g, &b_p)) {

        secp256k1_sha256_initialize(&hash);
        secp256k1_sha256_write(&hash, rnd32, sizeof(rnd32));
        secp256k1_sha256_finalize(&hash, rnd32_2);

        CHECK(secp256k1_ellswift_create(ctx, a_ell64, rnd32, rnd32_2));

    	CHECK(secp256k1_ellswift_xdh(ctx, symetric_key, b_ell64, a_ell64, rnd32, NULL, NULL));

    	AES256_CBC_init(&aes_ctx, symetric_key, a_ell64);
    	AES256_CBC_encrypt(&aes_ctx, ceil(size / 16), crypt, plain);

        return 1;
    }
    /* Only returned in case the provided pubkey is invalid. */
    return 0;
}



int secp256k1_ecies_decrypt(const secp256k1_context* ctx, unsigned char *plain, const unsigned char *crypt, const size_t size, const unsigned char *rnd32, const unsigned char *b_ell64, const unsigned char *a_ell64) {
    AES256_CBC_ctx aes_ctx;
    unsigned char symetric_key[32];
    
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(crypt != NULL);
    ARG_CHECK(rnd32 != NULL);
    ARG_CHECK(a_ell64 != NULL);
    if (secp256k1_ellswift_xdh(ctx, symetric_key, a_ell64, b_ell64, rnd32, NULL, NULL)) {
    	AES256_CBC_init(&aes_ctx, symetric_key, a_ell64);
    	AES256_CBC_decrypt(&aes_ctx, ceil(size / 16), plain, crypt);

        return 1;
    }
    /* Only returned in case the provided pubkey is invalid. */
    return 0;
}


#endif
