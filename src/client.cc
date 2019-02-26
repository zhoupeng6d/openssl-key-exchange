#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <functional>
#include "rpc/client.h"
#include "rpc/rpc_error.h"
#include "crypto.h"
#include "key_exchange.pb.h"
#include "hex_dump.h"


bool rpc_client_call(const std::string &addr, uint16_t port, uint8_t timeout_secs, std::function<void(rpc::client &)> rpc_method)
{
    int retry_cnt = 0;

    do {
        rpc::client client(addr, port);

        client.set_timeout(1000);

        try {
            rpc_method(client);
            return true;
        }
        catch(rpc::timeout &t) {
            printf("Call %s timeout:%s.\n\n", addr.c_str(), t.what());
            retry_cnt ++;
        }
    } while (retry_cnt < timeout_secs);

    return false;
}

bool key_exchange_check_response(const oke::KeyExchangeResponse &response, oke::KeyExchangeType type)
{
    if (response.key_exchange_type() != type)
    {
        std::cout << "Unable to match key exchange type." << std::endl;
        return false;
    }

    if (response.response_status().status_code() != oke::ResponseStatus_StatusCode_OK)
    {
        std::cout << "Key exchange response has error : " << response.response_status().error_message() << std::endl;
        return false;
    }

    return true;
}

bool key_exchange_initiate(const crypto::keys &key, crypto::devicekeys &server_key)
{
    oke::KeyExchangeRequest key_exchange_request;
    oke::KeyInfo        *key_info = new oke::KeyInfo();

    key_exchange_request.set_key_exchange_type(oke::KeyExchangeType::KEY_EXCHANGE_INITIATE);

    key_info->set_ecdh_public_key_65bytes(key.ecdh_pub_key, sizeof(crypto::keys::ecdh_pub_key));
    key_info->set_salt_32bytes(key.salt, sizeof(crypto::keys::salt));
    key_exchange_request.set_allocated_key_info(key_info);

    std::cout << ">>>>Send client's own key to server:" << std::endl;
    std::cout << "  ECDH-PUB-KEY:" << std::endl;
    dash::hex_dump(key_info->ecdh_public_key_65bytes());
    std::cout << "  Salt:" << std::endl;
    dash::hex_dump(key_info->salt_32bytes());

    std::string str_request;

    key_exchange_request.SerializeToString(&str_request);

    std::string str_response;

    bool ret = rpc_client_call("localhost", 7000, 2, std::bind([&str_request, &str_response](rpc::client &cli){
            str_response = cli.call("key_exchange", str_request).as<std::string>();
        }, std::placeholders::_1)
    );

    if (!ret)
    {
        std::cout << "Key exchange request failed." << std::endl;
        return false;
    }

    oke::KeyExchangeResponse response;

    if (!response.ParseFromString(str_response))
    {
        std::cout << "Key exchange parsing response failed." << std::endl;
        return false;
    }

    if (!key_exchange_check_response(response, oke::KeyExchangeType::KEY_EXCHANGE_INITIATE)) return false;

    std::cout << "<<<<Received server's key:" << std::endl;
    std::cout << "  ECDH-PUB-KEY:" << std::endl;
    dash::hex_dump(response.key_info().ecdh_public_key_65bytes());
    std::cout << "  Salt:" << std::endl;
    dash::hex_dump(response.key_info().salt_32bytes());

    std::string salt_32bytes = response.key_info().salt_32bytes();
    std::string pub_key_65bytes = response.key_info().ecdh_public_key_65bytes();

    if ((salt_32bytes.size() != 32) || (pub_key_65bytes.size() != 65))
    {
        std::cout << "Key length does not match." << std::endl;
        return false;
    }

    memcpy(server_key.ecdh_pub_key, pub_key_65bytes.data(), pub_key_65bytes.size());
    memcpy(server_key.salt, salt_32bytes.data(), salt_32bytes.size());

    return true;
}

bool key_calculate(const crypto::keys &key, crypto::devicekeys &server_key)
{
    uint8_t salt_xor[CRYPTO_SALT_LEN];

    if (!crypto::array_xor(key.salt, sizeof(crypto::keys::salt), server_key.salt, sizeof(crypto::devicekeys::salt), salt_xor))
    {
        std::cout << "xor calculation error." << std::endl;
        return false;
    }

    uint8_t shared_key[CRYPTO_ECDH_SHARED_LEN];

    if (!crypto::calc_ecdh_share_key(key.ecdh_pub_key, key.ecdh_priv_key, server_key.ecdh_pub_key, shared_key))
    {
        std::cout << "shared key calculation error." << std::endl;
        return false;
    }

    if (!crypto::generate_hkdf_bytes(shared_key, salt_xor, (uint8_t*)CRYPTO_KEY_INFO, strlen(CRYPTO_KEY_INFO), server_key.aes_key))
    {
        std::cout << "hkdf calculation error." << std::endl;
        return false;
    }

    std::cout << "Calculated the final AES-KEY:" << std::endl;
    dash::hex_dump(server_key.aes_key, CRYPTO_AES_KEY_LEN, std::cout);

    return true;
}

bool key_exchange_finalize()
{
    oke::KeyExchangeRequest key_exchange_request;

    key_exchange_request.set_key_exchange_type(oke::KeyExchangeType::KEY_EXCHANGE_FINALIZE);

    std::string str_request;
    std::string str_response;

    key_exchange_request.SerializeToString(&str_request);

    bool ret = rpc_client_call("localhost", 7000, 2, std::bind([&str_request, &str_response](rpc::client &cli){
            str_response = cli.call("key_exchange", str_request).as<std::string>();
        }, std::placeholders::_1)
    );

    if (!ret)
    {
        std::cout << "Key exchange request failed." << std::endl;
        return false;
    }

    oke::KeyExchangeResponse response;

    if (!response.ParseFromString(str_response))
    {
        std::cout << "Key exchange parsing response failed." << std::endl;
        return false;
    }

    if (!key_exchange_check_response(response, oke::KeyExchangeType::KEY_EXCHANGE_FINALIZE)) return false;

    std::cout << "======================Key exchange completed======================\n" << std::endl;

    return true;
}

bool encrypted_request(const crypto::devicekeys &dev_key, const std::string &param1, int32_t param2)
{
    oke::Plaintext plaintext;

    plaintext.set_param1(param1);
    plaintext.set_param2(param2);

    std::cout << "Send request to server:\n    param1:\"" << plaintext.param1() << "\"\n    param2: " << plaintext.param2() << std::endl;

    std::string str_plaintext;

    plaintext.SerializeToString(&str_plaintext);

    uint8_t rand_iv[CRYPTO_AES_IV_LEN];

    if (!crypto::rand_salt(rand_iv, CRYPTO_AES_IV_LEN))
    {
        std::cout << "random digit generation error." << std::endl;
        return false;
    }

    std::cout << "Serialized to hexadecimal format(plaintext):" << std::endl;
    dash::hex_dump(str_plaintext);

    std::string buf_ciphertext(str_plaintext.size(), '\0');

    uint8_t aes_tag[CRYPTO_AES_TAG_LEN];

    if (!crypto::aes_encrypt((unsigned char *)str_plaintext.data(), str_plaintext.size(),
                             dev_key.aes_key, rand_iv, (unsigned char *)&buf_ciphertext[0], aes_tag))
    {
        std::cout << "aes encryption error." << std::endl;
        return false;
    }

    uint8_t random[3];
    uint8_t hmac[CRYPTO_HMAC_SHA256];

    if (!crypto::rand_salt(random, 3))
    {
        std::cout << "random digit generation error." << std::endl;
        return false;
    }

    if (!crypto::hmac_sha256(hmac, random, 3, dev_key.ecdh_pub_key, CRYPTO_ECDH_PUB_LEN))
    {
        std::cout << "hmac calculation error." << std::endl;
        return false;
    }

    oke::Ciphertext *ciphertext = new oke::Ciphertext();

    ciphertext->set_cipher_version(CRYPTO_KEY_VERSION);
    ciphertext->set_aes_iv_12bytes(rand_iv, CRYPTO_AES_IV_LEN);
    ciphertext->set_aes_tag_16bytes(aes_tag, CRYPTO_AES_TAG_LEN);
    ciphertext->set_ciphertext_nbytes(std::move(buf_ciphertext));

    std::cout << "AES IV:" << std::endl;
    dash::hex_dump(ciphertext->aes_iv_12bytes());

    std::cout << "AES TAG:" << std::endl;
    dash::hex_dump(ciphertext->aes_tag_16bytes());

    std::cout << "AES encrypted (ciphertext):" << std::endl;
    dash::hex_dump(ciphertext->ciphertext_nbytes());

    oke::Token *token = new oke::Token();

    token->set_salt_3bytes(random, 3);
    token->set_hmac_3bytes(hmac, 3);

    oke::EncryptedRequest encrypted_request;

    encrypted_request.set_allocated_ciphertext(ciphertext);
    encrypted_request.set_allocated_token(token);

    std::string str_request;
    std::string str_response;

    encrypted_request.SerializeToString(&str_request);

    std::cout << ">>>>Send a encrypted request to server\nWaiting..." << std::endl;
    bool ret = rpc_client_call("localhost", 7000, 2, std::bind([&str_request, &str_response](rpc::client &cli){
            str_response = cli.call("ciphertext", str_request).as<std::string>();
        }, std::placeholders::_1)
    );

    if (!ret)
    {
        std::cout << "Ciphertext request failed." << std::endl;
        return false;
    }

    std::cout << "\n<<<<Received a response from server:" << std::endl;

    oke::EncryptedResponse encrypted_response;

    if (!encrypted_response.ParseFromString(str_response))
    {
        std::cout << "Encryption response parsing error." << std::endl;
        return false;
    }

    if (encrypted_response.response_status().status_code() != oke::ResponseStatus_StatusCode_OK)
    {
        std::cout << "encrypted response has error : " << encrypted_response.response_status().error_message() << std::endl;
        return false;
    }

    switch (encrypted_response.ciphertext().cipher_version())
    {
        case CRYPTO_KEY_VERSION: {
                if ((encrypted_response.ciphertext().aes_iv_12bytes().size() != CRYPTO_AES_IV_LEN)
                    || (encrypted_response.ciphertext().aes_tag_16bytes().size() != CRYPTO_AES_TAG_LEN))
                {
                    std::cout << "the length of aes iv or tag does not match." << std::endl;
                    return false;
                }

                std::string str_plaintext(encrypted_response.ciphertext().ciphertext_nbytes().size(), '\0');
                bool ret = crypto::aes_decrypt((unsigned char*)encrypted_response.ciphertext().ciphertext_nbytes().data(),
                                    encrypted_response.ciphertext().ciphertext_nbytes().size(),
                                    (unsigned char*)encrypted_response.ciphertext().aes_tag_16bytes().data(),
                                    dev_key.aes_key,
                                    (unsigned char*)encrypted_response.ciphertext().aes_iv_12bytes().data(),
                                    (unsigned char*)&str_plaintext[0]);
                if (!ret)
                {
                    std::cout << "aes decryption error." << std::endl;
                }

                oke::Plaintext plaintext;

                if (!plaintext.ParseFromString(str_plaintext))
                {
                    std::cout << "Plaintext paring error." << std::endl;
                }

                std::cout << "After AES decryption and protobuf parsing\n    param1:\"" << plaintext.param1() << "\"\n    param2: " << plaintext.param2() << std::endl;
            }
            break;
        default:
            std::cout << "unknow crypto version." << std::endl;
            return false;
            break;
    }

    return true;
}

void run_client()
{
    crypto::keys client_key;
    crypto::devicekeys server_key;

    /*
        Generate a pair of ECDH-KEY temporarily or you can load a pre-generated KEY from a file.
        If you are using a pre-generated KEY, you can register it‘s ECDH-PUBLIC-KEY on the server advance,
          so that the server can identify whether the client is legal.
    */
    if (!crypto::generate_ecdh_keys(client_key.ecdh_pub_key, client_key.ecdh_priv_key))
    {
        std::cout << "ECDH-KEY generation failed." << std::endl;
        return ;
    }

    /* Generate a random number that called salt */
    if (!crypto::rand_salt(client_key.salt, sizeof(crypto::keys::salt)))
    {
        std::cout << "Random salt generation failed." << std::endl;
    }

    /* Send the client's ECDH-PUB-KEY and salt to server, then wait for the server's ECDH-PUB-KEY and salt  */
    if (!key_exchange_initiate(client_key, server_key))
    {
        std::cout << "Key exchange initialization error." << std::endl;
        return ;
    }

    /* Calculate the final AES-KEY after receiving the server's key */
    if (!key_calculate(client_key, server_key))
    {
        std::cout << "Key calculation error." << std::endl;
        return ;
    }

    /* Tell the server that the key exchange is over. */
    if (!key_exchange_finalize())
    {
        std::cout << "Key exchange finalize error." << std::endl;
        return ;
    }

    std::cout << "Encrypted communication:\n\n" << std::endl;

    /* Encrypted communication */
    int32_t sequence = 0;
    while (1)
    {
        std::cout << "\n==================================================" << std::endl;
        if (!encrypted_request(server_key, "sequence", sequence++))
        {
            std::cout << "Request error." << std::endl;
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}
