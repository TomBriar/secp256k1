/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_ECIES_MAIN_
#define _SECP256K1_MODULE_ECIES_MAIN_

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_ecies.h"
#include "../../../include/secp256k1_ecdh.h"
#include "../../../include/secp256k1_ellsq.h"
#include "../../../include/secp256k1_aes.h"



int secp256k1_ecies_encrypt(const secp256k1_context* ctx, unsigned char *crypt32, const unsigned char *m32, const unsigned char *a_pr32, const unsigned char *b_ell64, const unsigned char *rnd16) {
	secp256k1_scalar ba_s, msg, crypt, a_pr;
	secp256k1_pubkey b_p, a_p;
    secp256k1_ge b_g, a_g;
    secp256k1_gej a_gej;
    AES256_CBC_ctx aes_ctx;
    
    unsigned char symetric_key[32];
    int overflow;
    
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(m32 != NULL);
    ARG_CHECK(a_pr32 != NULL);
    ARG_CHECK(b_ell64 != NULL);

    secp256k1_ellsq_decode(ctx, &b_p, b_ell64);

    if (secp256k1_pubkey_load(ctx, &b_g, &b_p)) {

    	secp256k1_scalar_set_b32(&a_pr, a_pr32, &overflow);
    	secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &a_gej, &a_pr);
    	secp256k1_ge_set_gej(&a_g, &a_gej);
    	secp256k1_pubkey_save(&a_p, &a_g);

    	CHECK(secp256k1_ecdh(ctx, &symetric_key, &b_p, a_pr32, NULL, NULL));

    	secp256k1_scalar_set_b32(&ba_s, &symetric_key, &overflow);

    	AES256_CBC_init(&aes_ctx, &ba_s, rnd16);
    	AES256_CBC_encrypt(&aes_ctx, 2, crypt32, m32);

        return 1;
    }
    /* Only returned in case the provided pubkey is invalid. */
    return 0;
}



int secp256k1_ecies_decrypt(const secp256k1_context* ctx, unsigned char *rem32, const unsigned char *crypt32, const unsigned char *b_pr32, const unsigned char *a_ell64, const unsigned char *iv16) {
    secp256k1_scalar ab_s, crypt, b_pr, remsg, ab_s_inv;
	secp256k1_pubkey b_p, a_p;
    secp256k1_ge b_g, a_g;
    secp256k1_gej b_gej;
    AES256_CBC_ctx aes_ctx;
    
    unsigned char symetric_key[32];
    int overflow;
    
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(crypt32 != NULL);
    ARG_CHECK(b_pr32 != NULL);
    ARG_CHECK(a_ell64 != NULL);

    secp256k1_ellsq_decode(ctx, &a_p, a_ell64);

    if (secp256k1_pubkey_load(ctx, &a_g, &a_p)) {
    	secp256k1_scalar_set_b32(&b_pr, b_pr32, &overflow);
    	secp256k1_scalar_set_b32(&crypt, crypt32, &overflow);
    	
    	secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &b_gej, &b_pr);
    	secp256k1_ge_set_gej(&b_g, &b_gej);
    	secp256k1_pubkey_save(&b_p, &b_g);

    	CHECK(secp256k1_ecdh(ctx, &symetric_key, &a_p, b_pr32, NULL, NULL));

    	secp256k1_scalar_set_b32(&ab_s, &symetric_key, &overflow);

    	AES256_CBC_init(&aes_ctx, &ab_s, iv16);
    	AES256_CBC_decrypt(&aes_ctx, 2, rem32, crypt32);
        return 1;
    }
    /* Only returned in case the provided pubkey is invalid. */
    return 0;
}


#endif
