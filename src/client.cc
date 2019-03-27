/*
 * @Author: Dash Zhou
 * @Date: 2019-03-27 18:28:48
 * @Last Modified by:   Dash Zhou
 * @Last Modified time: 2019-03-27 18:28:48
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


bool rpc_client_call(const std::string &addr, uint16_t port, int timeout_secs, int retry_cnt, std::function<void(rpc::client &)> rpc_method)
{
    int retrycnt = 0;

    do {
        rpc::client client(addr, port);

        client.set_timeout(timeout_secs*1000);

        try {
            rpc_method(client);
            return true;
        }
        catch(rpc::timeout &t) {
            printf("Call %s timeout:%s.\n\n", addr.c_str(), t.what());
            retrycnt ++;
        }
    } while (retrycnt < retry_cnt);

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

bool key_exchange_initiate(const crypto::ownkey_s &ownkey, crypto::peerkey_s &peerkey)
{
    oke::KeyExchangeRequest key_exchange_request;
    oke::KeyInfo           *key_info = new oke::KeyInfo();

    /* send ownkey to server */
    key_info->set_ecdh_public_key_65bytes(ownkey.ecdh_pub_key, sizeof(crypto::ownkey_s::ecdh_pub_key));
    key_info->set_salt_32bytes(ownkey.salt, sizeof(crypto::ownkey_s::salt));
    std::cout << ">>>>Send client's own key to server:" << std::endl;
    std::cout << "  ECDH-PUB-KEY:" << std::endl;
    dash::hex_dump(key_info->ecdh_public_key_65bytes());
    std::cout << "  Salt:" << std::endl;
    dash::hex_dump(key_info->salt_32bytes());

    std::string str_request;
    std::string str_response;
    key_exchange_request.set_allocated_key_info(key_info);
    key_exchange_request.set_key_exchange_type(oke::KeyExchangeType::KEY_EXCHANGE_INITIATE);
    key_exchange_request.SerializeToString(&str_request);
    bool ret = rpc_client_call("localhost", 7000, 2, 1, std::bind([&str_request, &str_response](rpc::client &cli){
            str_response = cli.call("key_exchange_request", str_request).as<std::string>();
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
    if (!key_exchange_check_response(response, oke::KeyExchangeType::KEY_EXCHANGE_INITIATE))
        return false;
    if ((response.key_info().salt_32bytes().size() != 32) || (response.key_info().ecdh_public_key_65bytes().size() != 65))
    {
        std::cout << "Key length does not match." << std::endl;
        return false;
    }

    std::cout << "<<<<Received server's key:" << std::endl;
    std::cout << "  ECDH-PUB-KEY:" << std::endl;
    dash::hex_dump(response.key_info().ecdh_public_key_65bytes());
    std::cout << "  Salt:" << std::endl;
    dash::hex_dump(response.key_info().salt_32bytes());
    memcpy(peerkey.ecdh_pub_key, response.key_info().ecdh_public_key_65bytes().data(), response.key_info().ecdh_public_key_65bytes().size());
    memcpy(peerkey.salt, response.key_info().salt_32bytes().data(), response.key_info().salt_32bytes().size());

    return true;
}

bool key_exchange_finalize()
{
    oke::KeyExchangeRequest key_exchange_request;
    std::string             str_request;
    std::string             str_response;

    /* Indicate the server that the key-exchange has finish. */
    key_exchange_request.set_key_exchange_type(oke::KeyExchangeType::KEY_EXCHANGE_FINALIZE);
    key_exchange_request.SerializeToString(&str_request);
    bool ret = rpc_client_call("localhost", 7000, 2, 1, std::bind([&str_request, &str_response](rpc::client &cli){
            str_response = cli.call("key_exchange_request", str_request).as<std::string>();
        }, std::placeholders::_1)
    );
    if (!ret)
    {
        std::cout << "Key exchange request failed." << std::endl;
        return false;
    }

    /* Waiting for the server to also complete the key exchange, return false if an error occurs  */
    oke::KeyExchangeResponse response;
    if (!response.ParseFromString(str_response))
    {
        std::cout << "Key exchange parsing response failed." << std::endl;
        return false;
    }
    if (!key_exchange_check_response(response, oke::KeyExchangeType::KEY_EXCHANGE_FINALIZE))
        return false;

    std::cout << "======================Key exchange completed======================\n" << std::endl;

    return true;
}

bool encrypted_request(const crypto::ownkey_s &ownkey, const crypto::peerkey_s &peerkey, const std::string &param1, int32_t param2)
{
    /* build the plaintext message and serialize */
    oke::Plaintext plaintext;
    std::string str_plaintext;
    plaintext.set_param1(param1);
    plaintext.set_param2(param2);
    plaintext.SerializeToString(&str_plaintext);
    std::cout << "Send request to server:\n    param1:\"" << plaintext.param1() << "\"\n    param2: " << plaintext.param2() << std::endl;
    std::cout << "Serialized to hexadecimal format(plaintext):" << std::endl;
    dash::hex_dump(str_plaintext);

    /* encrypted serialized plaintext to ciphertext */
    oke::Ciphertext *ciphertext = new oke::Ciphertext();
    if (!common::encrypt_plaintext(peerkey, str_plaintext, *ciphertext))
    {
        std::cout << "aes encryption error." << std::endl;
        delete ciphertext;
        return false;
    }

    /* Generate the client's token */
    oke::Token *token = new oke::Token();
    if (!common::generate_token(ownkey.ecdh_pub_key, *token))
    {
        std::cout << "token generation error." << std::endl;
        delete token;
        return false;
    }

    /* build the final encrypted_request  */
    oke::EncryptedRequest encrypted_request;
    encrypted_request.set_allocated_ciphertext(ciphertext);
    encrypted_request.set_allocated_token(token);
    std::string str_request;
    std::string str_response;
    encrypted_request.SerializeToString(&str_request);
    std::cout << ">>>>Send a encrypted request to server\nWaiting..." << std::endl;

    /* send the encrypted request to the server and wating for the server's response. */
    bool ret = rpc_client_call("localhost", 7000, 2, 1, std::bind([&str_request, &str_response](rpc::client &cli){
            str_response = cli.call("encrypted_request", str_request).as<std::string>();
        }, std::placeholders::_1)
    );
    if (!ret)
    {
        std::cout << "Encrypted request failed." << std::endl;
        return false;
    }

    /* parsing the received stream */
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
        case CRYPTO_VERSION: {
                if ((encrypted_response.ciphertext().aes_iv_12bytes().size() != CRYPTO_AES_IV_LEN)
                    || (encrypted_response.ciphertext().aes_tag_16bytes().size() != CRYPTO_AES_TAG_LEN))
                {
                    std::cout << "the length of aes iv or tag does not match." << std::endl;
                    return false;
                }

                /* parsing the plaintext stream */
                oke::Plaintext plaintext;
                if (!common::decrypt_ciphertext(peerkey, encrypted_response.ciphertext(), plaintext))
                {
                    std::cout << "aes decryption error." << std::endl;
                    return false;
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

int main()
{
    crypto::ownkey_s  client_key;
    crypto::peerkey_s server_key;

    /*
        Generate a pair of ECDH-KEY temporarily or you can load a pre-generated KEY from a file.
        If you are using a pre-generated KEY, you can register it‘s ECDH-PUBLIC-KEY on the server advance,
          so that the server can identify whether the client is legal.
    */
    if (!crypto::generate_ecdh_keys(client_key.ecdh_pub_key, client_key.ecdh_priv_key))
    {
        std::cout << "ECDH-KEY generation failed." << std::endl;
        return -1;
    }

    /* Generate a random number that called salt */
    if (!crypto::rand_salt(client_key.salt, sizeof(crypto::ownkey_s::salt)))
    {
        std::cout << "Random salt generation failed." << std::endl;
        return -1;
    }

    /* Send the client's ECDH-PUB-KEY and salt to server, then wait for the server's ECDH-PUB-KEY and salt  */
    if (!key_exchange_initiate(client_key, server_key))
    {
        std::cout << "Key exchange initialization error." << std::endl;
        return -1;
    }

    /* Calculate the final AES-KEY after receiving the server's key */
    if (!common::key_calculate(client_key, server_key))
    {
        std::cout << "Key calculation error." << std::endl;
        return -1;
    }

    /* Tell the server that the key exchange is over. */
    if (!key_exchange_finalize())
    {
        std::cout << "Key exchange finalize error." << std::endl;
        return -1;
    }

    std::cout << "Encrypted communication:\n\n" << std::endl;

    /* Encrypted communication */
    int32_t sequence = 0;
    while (1)
    {
        std::cout << "\n==================================================" << std::endl;
        if (!encrypted_request(client_key, server_key, "sequence", sequence++))
        {
            std::cout << "Request error." << std::endl;
            return -1;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    return 0;
}
