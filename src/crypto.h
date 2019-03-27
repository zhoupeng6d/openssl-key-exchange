/*
 * @Author: Dash Zhou
 * @Date: 2019-03-27 18:28:16
 * @Last Modified by:   Dash Zhou
 * @Last Modified time: 2019-03-27 18:28:16
 */

#ifndef __CRYPTO_H
#define __CRYPTO_H

#include <cstdint>
#include <cstring>
#include <string>

namespace crypto{

#define CRYPTO_ECDH_PUB_KEY_LEN      65
#define CRYPTO_ECDH_PRIV_KEY_LEN     32
#define CRYPTO_SALT_LEN              32
#define CRYPTO_ECDH_SHARED_KEY_LEN   32
#define CRYPTO_HMAC_SHA256           32
#define CRYPTO_AES_KEY_LEN           32
#define CRYPTO_AES_IV_LEN            12
#define CRYPTO_AES_TAG_LEN           16

#define CRYPTO_VERSION               1
#define CRYPTO_KEY_INFO              "ENCRYPTION"

struct ownkey_s {
    uint8_t ecdh_pub_key[CRYPTO_ECDH_PUB_KEY_LEN];
    uint8_t ecdh_priv_key[CRYPTO_ECDH_PRIV_KEY_LEN];
    uint8_t salt[CRYPTO_SALT_LEN];            // Just use in key exchange
};

struct peerkey_s {
    uint8_t ecdh_pub_key[CRYPTO_ECDH_PUB_KEY_LEN];
    uint8_t aes_key[CRYPTO_AES_KEY_LEN];
    uint8_t salt[CRYPTO_SALT_LEN];            // Just use in key exchange
};

bool rand_salt(uint8_t salt[], int32_t bytes);

bool generate_ecdh_keys(uint8_t ecdh_public_key[CRYPTO_ECDH_PUB_KEY_LEN],
                       uint8_t ecdh_private_key[CRYPTO_ECDH_PRIV_KEY_LEN]);

bool calc_ecdh_shared_key(const uint8_t ecdh1_public_key[CRYPTO_ECDH_PUB_KEY_LEN],
                        const uint8_t ecdh1_private_key[CRYPTO_ECDH_PRIV_KEY_LEN],
                        const uint8_t ecdh2_public_key[CRYPTO_ECDH_PUB_KEY_LEN],
                        uint8_t ecdh_shared_key[CRYPTO_ECDH_SHARED_KEY_LEN]);

bool hmac_sha256(uint8_t hmac[CRYPTO_HMAC_SHA256],
                const uint8_t key[], uint8_t key_len,
                const uint8_t data[], uint8_t data_len);

bool bytes_xor(const uint8_t data1[], int data1_len,
               const uint8_t data2[], int data2_len,
               uint8_t out[]);

bool generate_hkdf_bytes(const uint8_t ecdh_shared_key[CRYPTO_ECDH_SHARED_KEY_LEN],
                        const uint8_t salt[CRYPTO_SALT_LEN],
                        const uint8_t info[], int info_len,
                        uint8_t out[]);

bool aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext, unsigned char *tag);

bool aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *tag, const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext);
};

#endif
