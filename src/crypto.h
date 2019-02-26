
#ifndef __CRYPTO_H
#define __CRYPTO_H

#include <cstdint>
#include <cstring>
#include <string>

namespace crypto{

#define CRYPTO_ECDH_PUB_LEN      65
#define CRYPTO_ECDH_PRIV_LEN     32
#define CRYPTO_SALT_LEN          32
#define CRYPTO_ECDH_SHARED_LEN   32
#define CRYPTO_HMAC_SHA256       32
#define CRYPTO_AES_KEY_LEN       32
#define CRYPTO_AES_IV_LEN        12
#define CRYPTO_AES_TAG_LEN       16

#define CRYPTO_KEY_VERSION       1
#define CRYPTO_KEY_INFO          "ENCRYPTION"

struct keys {
    uint8_t ecdh_pub_key[CRYPTO_ECDH_PUB_LEN];
    uint8_t ecdh_priv_key[CRYPTO_ECDH_PRIV_LEN];

    uint8_t salt[CRYPTO_SALT_LEN];

    uint8_t aes_key[CRYPTO_AES_KEY_LEN];
};

struct devicekeys{
    uint8_t ecdh_pub_key[CRYPTO_ECDH_PUB_LEN];
    uint8_t aes_key[CRYPTO_AES_KEY_LEN];
    uint8_t salt[CRYPTO_SALT_LEN];  // Just use in key exchange


    devicekeys() {}
    devicekeys(uint8_t ecdh_pub_key[CRYPTO_ECDH_PUB_LEN], uint8_t aes_key[CRYPTO_AES_KEY_LEN])
    {
        memcpy(this->ecdh_pub_key, ecdh_pub_key, CRYPTO_ECDH_PUB_LEN);
        memcpy(this->aes_key, aes_key, CRYPTO_AES_KEY_LEN);
    }
    devicekeys(const std::string &ecdh_pub_key, const std::string &aes_key)
    {
        memcpy(this->ecdh_pub_key, ecdh_pub_key.data(), ecdh_pub_key.size());
        memcpy(this->aes_key, aes_key.data(), aes_key.size());
    }
};

bool rand_salt(uint8_t salt[], int32_t bytes);

bool generate_ecdh_keys(uint8_t ecdh_public_key[CRYPTO_ECDH_PUB_LEN],
                       uint8_t ecdh_private_key[CRYPTO_ECDH_PRIV_LEN]);

bool calc_ecdh_share_key(const uint8_t ecdh1_public_key[CRYPTO_ECDH_PUB_LEN],
                        const uint8_t ecdh1_private_key[CRYPTO_ECDH_PRIV_LEN],
                        const uint8_t ecdh2_public_key[CRYPTO_ECDH_PUB_LEN],
                        uint8_t ecdh_shared_key[CRYPTO_ECDH_SHARED_LEN]);

bool hmac_sha256(uint8_t hmac[CRYPTO_HMAC_SHA256],
                const uint8_t key[], uint8_t key_len,
                const uint8_t data[], uint8_t data_len);

bool array_xor(const uint8_t data1[], int data1_len,
        const uint8_t data2[], int data2_len,
        uint8_t out[]);

bool generate_hkdf_bytes(const uint8_t ecdh_shared_key[CRYPTO_ECDH_SHARED_LEN],
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
