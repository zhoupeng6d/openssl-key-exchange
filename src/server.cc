/*
 * @Author: Dash Zhou
 * @Date: 2019-03-27 18:28:34
 * @Last Modified by:   Dash Zhou
 * @Last Modified time: 2019-03-27 18:28:34
 */

#include <string>
#include "crypto.h"
#include "rpc/server.h"
#include "key_exchange.pb.h"
#include "hex_dump.h"
#include "common.h"

static crypto::ownkey_s      s_server_key;
static crypto::peerkey_s     s_client_key;

static oke::ResponseStatus* build_response_status(oke::ResponseStatus_StatusCode status_code, const std::string &error_msg)
{
    // This obj will be released when the oke::Response object loses scope
    oke::ResponseStatus *status = new oke::ResponseStatus();

    status->set_status_code(status_code);
    status->set_error_message(error_msg);

    return status;
}

static std::string handle_key_exchange_request(const std::string &data)
{
    oke::KeyExchangeRequest key_exchange_request;
    oke::KeyExchangeResponse key_exchange_response;

    oke::ResponseStatus_StatusCode status_code = oke::ResponseStatus_StatusCode_OK;
    std::string error_msg = "";
    std::string ret_string;

    if (!key_exchange_request.ParseFromString(data))
    {
        status_code = oke::ResponseStatus_StatusCode_INVALID_REQUEST;
        error_msg   = "Cannot parse proto from string";
        goto RET;
    }

    switch(key_exchange_request.key_exchange_type())
    {
        case oke::KeyExchangeType::KEY_EXCHANGE_INITIATE:
            {
                std::cout << "<<<<Received a KEY_EXCHANGE_INITIATE request." << std::endl;
                if ((key_exchange_request.key_info().ec_public_key_65bytes().size() != CRYPTO_EC_PUB_KEY_LEN)
                    || (key_exchange_request.key_info().salt_32bytes().size() != CRYPTO_SALT_LEN))
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "Key length does not match.";
                    break;
                }

                std::cout << "Client's EC-PUB-KEY:" << std::endl;
                dash::hex_dump(key_exchange_request.key_info().ec_public_key_65bytes());

                std::cout << "Client's salt:" << std::endl;
                dash::hex_dump(key_exchange_request.key_info().salt_32bytes());

                memcpy(s_client_key.ec_pub_key,
                        key_exchange_request.key_info().ec_public_key_65bytes().data(),
                        key_exchange_request.key_info().ec_public_key_65bytes().size());
                memcpy(s_client_key.salt,
                        key_exchange_request.key_info().salt_32bytes().data(),
                        key_exchange_request.key_info().salt_32bytes().size());

                oke::KeyInfo *key_info = new oke::KeyInfo();

                crypto::rand_salt(s_server_key.salt, sizeof(crypto::ownkey_s::salt));

                key_info->set_ec_public_key_65bytes(s_server_key.ec_pub_key, CRYPTO_EC_PUB_KEY_LEN);
                key_info->set_salt_32bytes(s_server_key.salt, CRYPTO_SALT_LEN);

                std::cout << ">>>>Send Server's own keys to client:" << std::endl;
                std::cout << "  ECDH-PUB-KEY:" <<std::endl;
                dash::hex_dump(key_info->ec_public_key_65bytes());
                dash::hex_dump(key_info->salt_32bytes());

                key_exchange_response.set_allocated_key_info(key_info);
            }
            break;
        case oke::KeyExchangeType::KEY_EXCHANGE_FINALIZE:
            {
                std::cout << "<<<<Received a KEY_EXCHANGE_FINALIZE request." << std::endl;

                if (!common::key_calculate(s_server_key, s_client_key))
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "Key calculation error.";
                    break;
                }

                std::cout << "======================Key exchange completed======================\n" << std::endl;
            }
            break;
        default:
            status_code = oke::ResponseStatus_StatusCode_ERROR;
            error_msg   = "Unknow request type";
            break;
    }

RET:
    key_exchange_response.set_key_exchange_type(key_exchange_request.key_exchange_type());
    key_exchange_response.set_allocated_response_status(
            build_response_status(status_code, error_msg));

    key_exchange_response.SerializeToString(&ret_string);

    return ret_string;
}

std::string demo_plaintext(const oke::Plaintext &plaintext)
{
    oke::Plaintext resp_plaintext;

    resp_plaintext.set_param1("sequence echo");
    resp_plaintext.set_param2(plaintext.param2());

    std::string str_resp_plaintext;

    resp_plaintext.SerializeToString(&str_resp_plaintext);

    return str_resp_plaintext;
}

std::string handle_encrypted_request(const std::string &data)
{
    oke::EncryptedRequest  encrypted_request;
    oke::EncryptedResponse encrypted_response;
    std::string            str_response;

    oke::ResponseStatus_StatusCode status_code = oke::ResponseStatus_StatusCode_OK;
    std::string                    error_msg = "";

    std::cout << "\n==================================================" << std::endl;

    if (!encrypted_request.ParseFromString(data))
    {
        status_code = oke::ResponseStatus_StatusCode_INVALID_REQUEST;
        error_msg = "encrypted request parsing error.";
    }

    switch (encrypted_request.ciphertext().cipher_version())
    {
        case CRYPTO_VERSION: {
                if ((encrypted_request.ciphertext().aes_iv_12bytes().size() != CRYPTO_AES_IV_LEN)
                    || (encrypted_request.ciphertext().aes_tag_16bytes().size() != CRYPTO_AES_TAG_LEN))
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "the length of aes iv or tag does not match.";
                    break;
                }

                if (!common::verify_token(s_client_key.ec_pub_key, encrypted_request.token()))
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "token check failed.";
                    break;
                }

                /* decrypt ciphertext to plaintext */
                oke::Plaintext plaintext;
                if (!common::decrypt_ciphertext(s_client_key, encrypted_request.ciphertext(), plaintext))
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "aes decryption error.";
                    break;
                }

                std::cout << "After protobuf parsing\n    param1:\"" << plaintext.param1() << "\"\n    param2: " << plaintext.param2() << std::endl;

                /* handle the plaintext and get a plaintext response */
                std::string str_resp_plaintext = demo_plaintext(plaintext);

                /* encrypt plaintext to ciphertext */
                oke::Ciphertext *ciphertext = new oke::Ciphertext();
                if (!common::encrypt_plaintext(s_client_key, str_resp_plaintext, *ciphertext))
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "aes encryption error.";
                    break;
                }

                encrypted_response.set_allocated_ciphertext(ciphertext);
            }
            break;
        default:
            break;
    }

RET:
    encrypted_response.set_allocated_response_status(build_response_status(status_code, error_msg));
    encrypted_response.SerializeToString(&str_response);
    return str_response;
}

int main()
{
    // Create a server that listens on port 7000, or whatever the user selected
    rpc::server srv("0.0.0.0", 7000);

    crypto::generate_ecdh_keys(s_server_key.ec_pub_key, s_server_key.ec_priv_key);

    srv.bind("key_exchange_request", &handle_key_exchange_request);

    srv.bind("encrypted_request", &handle_encrypted_request);

    std::cout << "server running..." << std::endl;

    /* run the server loop */
    srv.run();

    /* never to this */
    return 0;
}
