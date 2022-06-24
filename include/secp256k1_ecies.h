#ifndef _SECP256K1_ECIES_
# define _SECP256K1_ECIES_

# include "secp256k1.h"

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>

/* Encrypt a message with ECIES.
 *
 *  Returns: 1 when pubkey is valid.
 *  Args:    ctx:           pointer to a context object
 *  Out:     crypt32:       pointer to 32 bytes of encrypted message data.
 *  In:      m32:           pointer to 32 bytes of message data 
 *           a_pr32:        pointer to 32 bytes of entropy (must be unpredictable). Alice's private key.
 *           b_ell64:       pointer to 64 bytes of an encoded eliptic curve point(See ellsq). Bob's ELLSQ encoded public eliptic curve point.
 *
 * This function runs in unknown time.
 */
SECP256K1_API int secp256k1_ecies_encrypt(
    const secp256k1_context* ctx,
    const unsigned char *crypt32,
    const unsigned char *m32,
    const unsigned char *a_pr32,
    const unsigned char *b_ell64
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);//TODO: Need one for the ctx obj?

/* Decrypt a message with ECIES.
 *
 *  Returns: 1 when pubkey is valid.
 *  Args:    ctx:           pointer to a context object
 *  Out:     rem32:         pointer to 32 bytes of unencrypted message data.
 *  In:      crypt32:       pointer to 32 bytes of encrypted message data 
 *           b_pr32:        pointer to 32 bytes of entropy (must be unpredictable). Bob's private key.
 *           a_ell64:       pointer to 64 bytes of an encoded eliptic curve point(See ellsq). Alice's ELLSQ encoded public eliptic curve point.
 *
 * This function runs in unknown time.
 */
SECP256K1_API int secp256k1_ecies_decrypt(
    const secp256k1_context* ctx,
    const unsigned char *rem32,
    const unsigned char *crypt32,
    const unsigned char *b_pr32,
    const unsigned char *b_rnd32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);//TODO: Need one for the ctx obj?


# ifdef __cplusplus
}
# endif

#endif
