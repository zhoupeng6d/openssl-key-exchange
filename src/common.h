/*
 * @Author: Dash Zhou
 * @Date: 2019-03-27 18:28:04
 * @Last Modified by:   Dash Zhou
 * @Last Modified time: 2019-03-27 18:28:04
 */

#ifndef __COMMON_H
#define __COMMON_H

#include "hex_dump.h"
#include <iostream>
#include <string>
#include "crypto.h"
#include "key_exchange.pb.h"

namespace common
{

inline bool decrypt_ciphertext(const crypto::peerkey_s &peerkey, const oke::Ciphertext &ciphertext, oke::Plaintext &plaintext)
{
    std::cout << "AES IV:" << std::endl;
    dash::hex_dump(ciphertext.aes_iv_12bytes());
    std::cout << "AES TAG:" << std::endl;
    dash::hex_dump(ciphertext.aes_tag_16bytes());
    std::cout << "AES ciphertext:" << std::endl;
    dash::hex_dump(ciphertext.ciphertext_nbytes());

    std::string str_plaintext(ciphertext.ciphertext_nbytes().size(), '\0');
    bool ret = crypto::aes_decrypt((unsigned char*)ciphertext.ciphertext_nbytes().data(),
                        ciphertext.ciphertext_nbytes().size(),
                        (unsigned char*)ciphertext.aes_tag_16bytes().data(),
                        peerkey.aes_key,
                        (unsigned char*)ciphertext.aes_iv_12bytes().data(),
                        (unsigned char*)&str_plaintext[0]);
    if (!ret) return false;

    std::cout << "Plaintext:" << std::endl;
    dash::hex_dump(str_plaintext);
    if (!plaintext.ParseFromString(str_plaintext))
    {
        std::cout << "plaintext parsing error." << std::endl;
        return false;
    }

    return true;
}

inline bool encrypt_plaintext(const crypto::peerkey_s &peerkey, const std::string &str_plaintext, oke::Ciphertext &ciphertext)
{
    std::string str_ciphertext(str_plaintext.size(), '\0');
    uint8_t rand_iv[CRYPTO_AES_IV_LEN];
    uint8_t aes_tag[CRYPTO_AES_TAG_LEN];


    if (!crypto::rand_salt(rand_iv, CRYPTO_AES_IV_LEN))
    {
        return false;
    }

    bool ret = crypto::aes_encrypt((unsigned char *)str_plaintext.data(), str_plaintext.size(),
                                   peerkey.aes_key, rand_iv, (unsigned char *)&str_ciphertext[0], aes_tag);
    if (!ret)
    {
        return false;
    }

    ciphertext.set_cipher_version(CRYPTO_VERSION);
    ciphertext.set_aes_iv_12bytes(rand_iv, CRYPTO_AES_IV_LEN);
    ciphertext.set_aes_tag_16bytes(aes_tag, CRYPTO_AES_TAG_LEN);
    ciphertext.set_ciphertext_nbytes(std::move(str_ciphertext));

    return true;
}

inline bool verify_token(const uint8_t ecdh_pub_key[CRYPTO_EC_PUB_KEY_LEN], const oke::Token &token)
{
    uint8_t hmac_256[CRYPTO_HMAC_SHA256];

    bool ret = crypto::hmac_sha256(hmac_256,
         (uint8_t *)token.salt_3bytes().data(), token.salt_3bytes().size(),
         ecdh_pub_key, CRYPTO_EC_PUB_KEY_LEN);
    if (!ret)
    {
        std::cout << "hmac calculation error." << std::endl;
        return false;
    }

    if (0 != memcmp(token.hmac_3bytes().data(), hmac_256, 3))
    {
        std::cout << "Token check failed" << std::endl;
        return false;
    }

    return true;
}

inline bool generate_token(const uint8_t ecdh_pub_key[CRYPTO_EC_PUB_KEY_LEN], oke::Token &token)
{
    uint8_t random_digit[3];
    uint8_t hmac_256[CRYPTO_HMAC_SHA256];


    if (!crypto::rand_salt(random_digit, 3))
    {
        std::cout << "random digit generation error." << std::endl;
        return false;
    }

    if (!crypto::hmac_sha256(hmac_256, random_digit, 3, ecdh_pub_key, CRYPTO_EC_PUB_KEY_LEN))
    {
        std::cout << "hmac calculation error." << std::endl;
        return false;
    }

    token.set_salt_3bytes(random_digit, 3);
    token.set_hmac_3bytes(hmac_256, 3);

    return true;
}

inline bool key_calculate(const crypto::ownkey_s &ownkey, crypto::peerkey_s &peerkey)
{
    /* XOR the ownkey and peerkey to one array */
    uint8_t salt_xor[CRYPTO_SALT_LEN];
    if (!crypto::bytes_xor(ownkey.salt, sizeof(crypto::ownkey_s::salt), peerkey.salt, sizeof(crypto::peerkey_s::salt), salt_xor))
    {
        std::cout << "xor calculation error." << std::endl;
        return false;
    }

    /* Calculate the shared key using own public and private keys and the public key of the other party */
    uint8_t shared_key[CRYPTO_ECDH_SHARED_KEY_LEN];
    if (!crypto::calc_ecdh_shared_key(ownkey.ec_pub_key, ownkey.ec_priv_key, peerkey.ec_pub_key, shared_key))
    {
        std::cout << "shared key calculation error." << std::endl;
        return false;
    }

    /* Using HKDF to calculate the final AES key */
    if (!crypto::generate_hkdf_bytes(shared_key, salt_xor, (uint8_t*)CRYPTO_KEY_INFO, strlen(CRYPTO_KEY_INFO), peerkey.aes_key))
    {
        std::cout << "hkdf calculation error." << std::endl;
        return false;
    }

    std::cout << "Calculated the final AES-KEY:" << std::endl;
    dash::hex_dump(peerkey.aes_key, CRYPTO_AES_KEY_LEN, std::cout);

    return true;
}

}

#endif