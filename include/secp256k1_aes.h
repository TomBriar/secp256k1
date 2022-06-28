#ifndef _SECP256K1_AES_
# define _SECP256K1_AES_

# include "secp256k1.h"

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>

typedef struct {
    uint16_t slice[8];
} AES_state;

typedef struct {
    AES_state rk[11];
} AES128_ctx;

typedef struct {
    AES_state rk[13];
} AES192_ctx;

typedef struct {
    AES_state rk[15];
} AES256_ctx;

typedef struct {
    AES128_ctx ctx;
    uint8_t iv[16]; /* iv is updated after each use */
} AES128_CBC_ctx;

typedef struct {
    AES192_ctx ctx;
    uint8_t iv[16]; /* iv is updated after each use */
} AES192_CBC_ctx;

typedef struct {
    AES256_ctx ctx;
    uint8_t iv[16]; /* iv is updated after each use */
} AES256_CBC_ctx;


/* Initilize an AES encryption.
 *
 *  Returns: 1 when pubkey is valid.
 *  Args:    ctx:           pointer to a AES128_ctx object
 *  In:      key16:         pointer to 16 bytes of entropy (must be unpredictable).
 *
 * This function runs in unknown time.
 */
/*
SECP256K1_API void AES128_init(
    AES128_ctx* ctx, 
    const unsigned char* key16
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);
*/
/* Encrypts a message with AES128.
 *
 *  Returns: 1 when pubkey is valid.
 *  Args:    ctx:           pointer to a AES128_ctx object
 *  Out:     cipher16:      pointer to 16 bytes of cipherd text
 *  In:      blocks:        a size_t object of the number of 16 byte blocks to encrypt
 *           plain16:       pointer to 16 bytes of plain text to be encrypted
 *
 *
 * This function runs in unknown time.
 */
/*
SECP256K1_API void AES128_encrypt(
    const AES128_ctx* ctx, 
    size_t blocks, 
    unsigned char* cipher16, 
    const unsigned char* plain16
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);
*/


/*
void AES128_encrypt(const AES128_ctx* ctx, size_t blocks, unsigned char* cipher16, const unsigned char* plain16);
void AES128_decrypt(const AES128_ctx* ctx, size_t blocks, unsigned char* plain16, const unsigned char* cipher16);

void AES192_init(AES192_ctx* ctx, const unsigned char* key24);
void AES192_encrypt(const AES192_ctx* ctx, size_t blocks, unsigned char* cipher16, const unsigned char* plain16);
void AES192_decrypt(const AES192_ctx* ctx, size_t blocks, unsigned char* plain16, const unsigned char* cipher16);

void AES256_init(AES256_ctx* ctx, const unsigned char* key32);
void AES256_encrypt(const AES256_ctx* ctx, size_t blocks, unsigned char* cipher16, const unsigned char* plain16);
void AES256_decrypt(const AES256_ctx* ctx, size_t blocks, unsigned char* plain16, const unsigned char* cipher16);

/* Initilize an AES128_CBC encryption.
 *
 *  Returns: void.
 *  Args:    ctx:           pointer to a AES128_CBC_ctx object
 *  In:      key16:         pointer to 16 bytes of entropy (must be unpredictable).
 *           iv:            pointer to a unint8_t object of entropy (must be unpredictable).
 *
 * This function runs in unknown time.
 */

SECP256K1_API void AES128_CBC_init(
    AES128_CBC_ctx* ctx, 
    const unsigned char* key16,
    const uint8_t* iv
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/* Encrypts a message with AES128_CBC encryption.
 *
 *  Returns: void.
 *  Args:    ctx:           pointer to a AES128_CBC_ctx object
 *  Out:     encrypted:     pointer to an array containing the encrypted message
 *  In:      blocks:        size_t containing the number of 16 byte blocks to encrypt
 *           plain:         pointer to an array containing the plain text to encrypt
 *
 * This function runs in unknown time.
 */

SECP256K1_API void AES128_CBC_encrypt(
    AES128_CBC_ctx* ctx, 
    size_t blocks, 
    unsigned char* encrypted, 
    const unsigned char* plain
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/* Decrypts a message with AES128_CBC Decryption.
 *
 *  Returns: void.
 *  Args:    ctx:           pointer to a AES128_CBC_ctx object
 *  Out:     plain:         pointer to an array containing the plain text message
 *  In:      blocks:        size_t containing the number of 16 byte blocks to decrypt 
 *           encrypted:     pointer to an array containing the encrypted text to decrypt
 *
 * This function runs in unknown time.
 */

SECP256K1_API void AES128_CBC_decrypt(
    AES128_CBC_ctx* ctx, 
    size_t blocks, 
    unsigned char* plain, 
    const unsigned char *encrypted
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/* Initilize an AES192_CBC encryption.
 *
 *  Returns: void.
 *  Args:    ctx:           pointer to a AES192_CBC_ctx object
 *  In:      key16:         pointer to 16 bytes of entropy (must be unpredictable).
 *           iv:            pointer to a unint8_t object of entropy (must be unpredictable).
 *
 * This function runs in unknown time.
 */

SECP256K1_API void AES192_CBC_init(
    AES192_CBC_ctx* ctx, 
    const unsigned char* key16,
    const uint8_t* iv
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/* Encrypts a message with AES192_CBC encryption.
 *
 *  Returns: void.
 *  Args:    ctx:           pointer to a AES192_CBC_ctx object
 *  Out:     encrypted:     pointer to an array containing the encrypted message
 *  In:      blocks:        size_t containing the number of 16 byte blocks to encrypt
 *           plain:         pointer to an array containing the plain text to encrypt
 *
 * This function runs in unknown time.
 */

SECP256K1_API void AES192_CBC_encrypt(
    AES192_CBC_ctx* ctx, 
    size_t blocks, 
    unsigned char* encrypted, 
    const unsigned char* plain
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/* Decrypts a message with AES192_CBC Decryption.
 *
 *  Returns: void.
 *  Args:    ctx:           pointer to a AES192_CBC_ctx object
 *  Out:     plain:         pointer to an array containing the plain text message
 *  In:      blocks:        size_t containing the number of 16 byte blocks to decrypt 
 *           encrypted:     pointer to an array containing the encrypted text to decrypt
 *
 * This function runs in unknown time.
 */

SECP256K1_API void AES192_CBC_decrypt(
    AES192_CBC_ctx* ctx, 
    size_t blocks, 
    unsigned char* plain, 
    const unsigned char *encrypted
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/* Initilize an AES256_CBC encryption.
 *
 *  Returns: void.
 *  Args:    ctx:           pointer to a AES256_CBC_ctx object
 *  In:      key16:         pointer to 16 bytes of entropy (must be unpredictable).
 *           iv:            pointer to a unint8_t object of entropy (must be unpredictable).
 *
 * This function runs in unknown time.
 */

SECP256K1_API void AES256_CBC_init(
    AES256_CBC_ctx* ctx, 
    const unsigned char* key16,
    const uint8_t* iv
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/* Encrypts a message with AES256_CBC encryption.
 *
 *  Returns: void.
 *  Args:    ctx:           pointer to a AES256_CBC_ctx object
 *  Out:     encrypted:     pointer to an array containing the encrypted message
 *  In:      blocks:        size_t containing the number of 16 byte blocks to encrypt
 *           plain:         pointer to an array containing the plain text to encrypt
 *
 * This function runs in unknown time.
 */

SECP256K1_API void AES256_CBC_encrypt(
    AES256_CBC_ctx* ctx, 
    size_t blocks, 
    unsigned char* encrypted, 
    const unsigned char* plain
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/* Decrypts a message with AES256_CBC Decryption.
 *
 *  Returns: void.
 *  Args:    ctx:           pointer to a AES256_CBC_ctx object
 *  Out:     plain:         pointer to an array containing the plain text message
 *  In:      blocks:        size_t containing the number of 16 byte blocks to decrypt 
 *           encrypted:     pointer to an array containing the encrypted text to decrypt
 *
 * This function runs in unknown time.
 */

SECP256K1_API void AES256_CBC_decrypt(
    AES256_CBC_ctx* ctx, 
    size_t blocks, 
    unsigned char* plain, 
    const unsigned char *encrypted
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

# ifdef __cplusplus
}
# endif

#endif
