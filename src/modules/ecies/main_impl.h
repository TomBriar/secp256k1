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



int secp256k1_ecies_encrypt(const secp256k1_context* ctx, const unsigned char *crypt32, const unsigned char *m32, const unsigned char *a_pr32, const unsigned char *b_ell64) {
	secp256k1_scalar ba_s, msg, crypt, a_pr;
	secp256k1_pubkey b_p, a_p;
    secp256k1_ge b_g, a_g;
    secp256k1_gej a_gej;
    
    unsigned char symetric_key[32];
    int overflow, a;
    
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(m32 != NULL);
    ARG_CHECK(crypt32 != NULL);
    ARG_CHECK(a_pr32 != NULL);
    ARG_CHECK(b_ell64 != NULL);

    secp256k1_ellsq_decode(ctx, &b_p, b_ell64);

    if (secp256k1_pubkey_load(ctx, &b_g, &b_p)) {
    	secp256k1_scalar_set_b32(&a_pr, a_pr32, &overflow);
    	secp256k1_scalar_set_b32(&msg, m32, &overflow);
    	
    	secp256k1_ecmult_gen(ctx, &a_gej, &a_pr);
    	secp256k1_ge_set_gej(&a_g, &a_gej);
    	secp256k1_pubkey_save(&a_p, &a_g);

    	secp256k1_ecdh(ctx, &symetric_key, &b_p, &a_pr, NULL, NULL);

    	printf("symetric_key: ");
	    for ( a=0; a < 32; a = a + 1 ){
	      	printf("%u, ", symetric_key[a]);
	   	}
	   	printf(";\n\n");

    	secp256k1_scalar_set_b32(&ba_s, &symetric_key, &overflow);
    	secp256k1_scalar_mul(&crypt, &ba_s, &msg);
    	secp256k1_scalar_get_b32(crypt32, &crypt);
        return 1;
    }
    /* Only returned in case the provided pubkey is invalid. */
    return 0;
}

int secp256k1_ecies_decode(const secp256k1_context* ctx, const unsigned char *rem32, const unsigned char *crypt32, const unsigned char *b_pr32, const unsigned char *a_ell64) {
    // secp256k1_ge a_g;
    // secp256k1_gej a_gej;
    // secp256k1_scalar b_pr, ab_s, msg, crypt;
    // secp256k1_pubkey a_p;
    // unsigned char symetric_key[32];
    // int overflow, a;

    // VERIFY_CHECK(ctx != NULL);
    // ARG_CHECK(a_ell64 != NULL);
    // ARG_CHECK(crypted32 != NULL);
    // ARG_CHECK(b_rnd32 != NULL);

    // secp256k1_ellsq_decode(ctx, &a_p, a_ell64);

    // if (secp256k1_pubkey_load(ctx, &a_g, &a_p)) {

    // 	secp256k1_scalar_set_b32(&b_pr, b_rnd32, &overflow);
    // 	secp256k1_ecdh(ctx, &symetric_key, &a_p, &b_pr, NULL, NULL);//b_rnd32 should be the scalar b_pr bobs private key.

    

    // 	secp256k1_scalar_set_b32(&ab_s, &symetric_key, &overflow);
    // 	secp256k1_scalar_mul(&crypt, &ab_s, &msg);

    // 	secp256k1_scalar_get_b32(m32, &crypt);
    //     return 1;
    // }
    // /* Only returned in case the provided pubkey is invalid. */
    return 0;
}

#endif
