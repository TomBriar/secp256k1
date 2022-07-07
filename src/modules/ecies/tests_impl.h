/**********************************************************************
 * Copyright (c) 2020 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_ECIES_TEST_
#define _SECP256K1_MODULE_ECIES_TEST_

void run_ecies_tests(void) {
    unsigned char rnd32[32], a_ell64[64];
    unsigned char b_rnd32[32], b_ell_rnd32[32], b_ell64[64];
    unsigned char msg[32], crypt[32], remsg[32];
    secp256k1_pubkey b_pubkey;
    secp256k1_scalar msg_s, remsg_s, b_pr, encrypted;
    secp256k1_gej b_gej;
    secp256k1_ge b_g;
    int overflow, iter;

    /*Prepare Alice's ellsq encoded public key and private key.*/
    secp256k1_testrand256(rnd32);

    /*Prepare Bob's ellsq encoded public key and private key.*/
    secp256k1_testrand256(b_rnd32);
    secp256k1_testrand256(b_ell_rnd32);
    secp256k1_scalar_set_b32(&b_pr, b_rnd32, &overflow);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &b_gej, &b_pr);
    secp256k1_ge_set_gej(&b_g, &b_gej);
    secp256k1_pubkey_save(&b_pubkey, &b_g);
    secp256k1_ellsq_encode(ctx, b_ell64, b_ell_rnd32, &b_pubkey);

    /*Random Message*/
    secp256k1_testrand256(msg);

    /*Encrypt*/
    secp256k1_ecies_encrypt(ctx, crypt, a_ell64, msg, 32, rnd32, b_ell64);

    /*Decrypt*/
   	secp256k1_ecies_decrypt(ctx, remsg, crypt, 32, b_rnd32, a_ell64);

    /*Test*/
    secp256k1_scalar_set_b32(&msg_s, msg, &overflow);
    secp256k1_scalar_set_b32(&encrypted, crypt, &overflow);
    secp256k1_scalar_set_b32(&remsg_s, remsg, &overflow);
    CHECK(!secp256k1_scalar_eq(&msg_s, &encrypted));
    CHECK(secp256k1_scalar_eq(&msg_s, &remsg_s));



    /*Zero Message*/
    for (iter=0; iter < 32; iter = iter + 1) {
      msg[iter] = 0;
    }

    /*Encrypt*/
    secp256k1_ecies_encrypt(ctx, crypt, a_ell64, msg, 32, rnd32, b_ell64);

    /*Decrypt*/
    secp256k1_ecies_decrypt(ctx, remsg, crypt, 32, b_rnd32, a_ell64);

    /*Test*/
    secp256k1_scalar_set_b32(&msg_s, msg, &overflow);
    secp256k1_scalar_set_b32(&encrypted, crypt, &overflow);
    secp256k1_scalar_set_b32(&remsg_s, remsg, &overflow);
    CHECK(!secp256k1_scalar_eq(&msg_s, &encrypted));
    CHECK(secp256k1_scalar_eq(&msg_s, &remsg_s));
}

#endif
