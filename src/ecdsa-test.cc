/*
 * @Date: 2020-01-08 15:52:47
 * @LastEditors  : Dash Zhou
 * @LastEditTime : 2020-01-08 17:02:15
 */
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <functional>
#include "rpc/client.h"
#include "rpc/rpc_error.h"
#include "crypto.h"
#include "common.h"
#include "key_exchange.pb.h"
#include "hex_dump.h"


static void hex_dump(unsigned char *buf, int len)
{
    int i;

    for (i = 0; i < len; i++)
    {
        if (i && (i % 16 == 0))
        {
            printf("\n");
        }

        printf("%02X ", buf[i]);
        //printf("%c", buf[i]);
    }
    printf("\n");
}

int main()
{
    crypto::ownkey_s  client_key;

    if (!crypto::generate_ecdh_keys(client_key.ec_pub_key, client_key.ec_priv_key))
    {
        std::cout << "ECDH-KEY generation failed." << std::endl;
        return -1;
    }

    std::string data = "hello world";

    uint8_t hmac[CRYPTO_HMAC_SHA256] = {0};
    if (!crypto::hmac_sha256(hmac, (uint8_t*)"none", strlen("none"), (uint8_t*)data.c_str(), data.length()))
    {
        std::cout << "hmac generation failed." << std::endl;
        return -1;
    }

    /* generate a signature using ec private key */
    uint8_t sign[CRYPTO_ECDSA_SIG_LEN] = {0};
    if (!crypto::ecdsa_sign(client_key.ec_priv_key, hmac, CRYPTO_HMAC_SHA256, sign))
    {
        std::cout << "sign generation failed." << std::endl;
        return -1;
    }

    std::cout << "hmac:" << std::endl;
    hex_dump(hmac, CRYPTO_HMAC_SHA256);

    std::cout << "sign:" << std::endl;
    hex_dump(sign, CRYPTO_ECDSA_SIG_LEN);

    /* using ec public key to verify signature */
    if (!crypto::ecdsa_verify(client_key.ec_pub_key, hmac, CRYPTO_HMAC_SHA256, sign))
    {
        std::cout << "ecdsa verify error." << std::endl;
        return -1;
    }

    std::cout << "all ok" << std::endl;
    return 0;
}
