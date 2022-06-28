/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_ECIES_TEST_
#define _SECP256K1_MODULE_ECIES_TEST_

void run_ecies_tests(void) {
    unsigned char a_rnd32[32], a_ell_rnd32[32], a_ell64[64];
    unsigned char b_rnd32[32], b_ell_rnd32[32], b_ell64[64];
    unsigned char m32[32], crypt32[32], rem32[32], iv16[32];
    secp256k1_pubkey a_pubkey, b_pubkey;
    secp256k1_scalar a_pr, b_pr, msg, remsg;
    secp256k1_gej a_gej, b_gej;
    secp256k1_ge a_g, b_g;
    int overflow, iter;

    /*Prepare Alice's ellsq encoded public key and private key.*/
    secp256k1_testrand256(&a_rnd32);
    secp256k1_scalar_set_b32(&a_pr, &a_rnd32, &overflow);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &a_gej, &a_pr);
    secp256k1_ge_set_gej(&a_g, &a_gej);
    secp256k1_pubkey_save(&a_pubkey, &a_g);
    secp256k1_ellsq_encode(ctx, &a_ell64, &a_ell_rnd32, &a_pubkey);

    /*Prepare Bob's ellsq encoded public key and private key.*/
    secp256k1_testrand256(&b_rnd32);
    secp256k1_scalar_set_b32(&b_pr, &b_rnd32, &overflow);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &b_gej, &b_pr);
    secp256k1_ge_set_gej(&b_g, &b_gej);
    secp256k1_pubkey_save(&b_pubkey, &b_g);
    secp256k1_ellsq_encode(ctx, &b_ell64, &b_ell_rnd32, &b_pubkey);

    /*Random Message*/
    secp256k1_testrand256(&m32);

    /*Nonce*/
    secp256k1_testrand256(&iv16);

    /*Encrypt*/
    secp256k1_ecies_encrypt(ctx, &crypt32, &m32, &a_rnd32, &b_ell64, &iv16);

    /*Decrypt*/
   	secp256k1_ecies_decrypt(ctx, &rem32, &crypt32, &b_rnd32, &a_ell64, &iv16);

    /*Test*/
    secp256k1_scalar_set_b32(&msg, &m32, &overflow);
    secp256k1_scalar_set_b32(&remsg, &rem32, &overflow);
    CHECK(secp256k1_scalar_eq(&msg, &remsg));
}

#endif
