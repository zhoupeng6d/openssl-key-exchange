
#include <string>
#include "crypto.h"
#include "rpc/server.h"
#include "key_exchange.pb.h"
#include "hex_dump.h"

static crypto::keys                    s_server_key;
static crypto::devicekeys              s_client_key;

static oke::ResponseStatus* build_response_status(oke::ResponseStatus_StatusCode status_code, const std::string &error_msg)
{
    // This obj will be released when the oke::Response object loses scope
    oke::ResponseStatus *status = new oke::ResponseStatus();

    status->set_status_code(status_code);
    status->set_error_message(error_msg);

    return status;
}

std::string handle_key_exchange(const std::string &data)
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
                if ((key_exchange_request.key_info().ecdh_public_key_65bytes().size() != CRYPTO_ECDH_PUB_LEN)
                    || (key_exchange_request.key_info().salt_32bytes().size() != CRYPTO_SALT_LEN))
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "Key length does not match.";
                    break;
                }

                std::cout << "Client's ECDH-PUB-KEY:" << std::endl;
                dash::hex_dump(key_exchange_request.key_info().ecdh_public_key_65bytes());

                std::cout << "Client's salt:" << std::endl;
                dash::hex_dump(key_exchange_request.key_info().salt_32bytes());

                memcpy(s_client_key.ecdh_pub_key,
                        key_exchange_request.key_info().ecdh_public_key_65bytes().data(),
                        key_exchange_request.key_info().ecdh_public_key_65bytes().size());
                memcpy(s_client_key.salt,
                        key_exchange_request.key_info().salt_32bytes().data(),
                        key_exchange_request.key_info().salt_32bytes().size());

                oke::KeyInfo *key_info = new oke::KeyInfo();

                crypto::rand_salt(s_server_key.salt, sizeof(crypto::keys::salt));

                key_info->set_ecdh_public_key_65bytes(s_server_key.ecdh_pub_key, CRYPTO_ECDH_PUB_LEN);
                key_info->set_salt_32bytes(s_server_key.salt, CRYPTO_SALT_LEN);

                std::cout << ">>>>Send Server's own keys to client:" << std::endl;
                std::cout << "  ECDH-PUB-KEY:" <<std::endl;
                dash::hex_dump(key_info->ecdh_public_key_65bytes());
                dash::hex_dump(key_info->salt_32bytes());

                key_exchange_response.set_allocated_key_info(key_info);
            }
            break;
        case oke::KeyExchangeType::KEY_EXCHANGE_FINALIZE:
            {
                std::cout << "<<<<Received a KEY_EXCHANGE_FINALIZE request." << std::endl;
                uint8_t salt_xor[CRYPTO_SALT_LEN];

                crypto::array_xor(s_server_key.salt, CRYPTO_SALT_LEN,
                                  s_client_key.salt, CRYPTO_SALT_LEN,
                                  salt_xor);

                uint8_t ecdh_shared_key[CRYPTO_ECDH_SHARED_LEN];
                if (!crypto::calc_ecdh_share_key(s_server_key.ecdh_pub_key, s_server_key.ecdh_priv_key,
                                            s_client_key.ecdh_pub_key,
                                            ecdh_shared_key))
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "ecdh shared key calculation error.";
                    break;
                }

                if (!crypto::generate_hkdf_bytes(ecdh_shared_key, salt_xor,
                                            (uint8_t*)CRYPTO_KEY_INFO, strlen(CRYPTO_KEY_INFO), s_client_key.aes_key))
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "hkdf calculation error.";
                    break;
                }

                std::cout << "Calculated the final AES-KEY:" << std::endl;
                dash::hex_dump(s_client_key.aes_key, CRYPTO_AES_KEY_LEN, std::cout);

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

std::string handle_plaintext(const oke::Plaintext &plaintext)
{
    oke::Plaintext resp_plaintext;

    resp_plaintext.set_param1("sequence echo");
    resp_plaintext.set_param2(plaintext.param2());

    std::string str_resp_plaintext;

    resp_plaintext.SerializeToString(&str_resp_plaintext);

    return str_resp_plaintext;
}

std::string handle_ciphertext(const std::string &data)
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
        case CRYPTO_KEY_VERSION: {
                if ((encrypted_request.ciphertext().aes_iv_12bytes().size() != CRYPTO_AES_IV_LEN)
                    || (encrypted_request.ciphertext().aes_tag_16bytes().size() != CRYPTO_AES_TAG_LEN))
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "the length of aes iv or tag does not match.";
                    break;
                }

                std::cout << "AES IV:" << std::endl;
                dash::hex_dump(encrypted_request.ciphertext().aes_iv_12bytes());

                std::cout << "AES TAG:" << std::endl;
                dash::hex_dump(encrypted_request.ciphertext().aes_tag_16bytes());

                std::cout << "AES ciphertext:" << std::endl;
                dash::hex_dump(encrypted_request.ciphertext().ciphertext_nbytes());

                std::string str_plaintext(encrypted_request.ciphertext().ciphertext_nbytes().size(), '\0');
                bool ret = crypto::aes_decrypt((unsigned char*)encrypted_request.ciphertext().ciphertext_nbytes().data(),
                                    encrypted_request.ciphertext().ciphertext_nbytes().size(),
                                    (unsigned char*)encrypted_request.ciphertext().aes_tag_16bytes().data(),
                                    s_client_key.aes_key,
                                    (unsigned char*)encrypted_request.ciphertext().aes_iv_12bytes().data(),
                                    (unsigned char*)&str_plaintext[0]);
                if (!ret)
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "aes decryption error.";
                    break;
                }

                std::cout << "Plaintext:" << std::endl;
                dash::hex_dump(str_plaintext);

                oke::Plaintext plaintext;

                if (!plaintext.ParseFromString(str_plaintext))
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "plaintext paring error.";
                    break;
                }

                std::cout << "After protobuf parsing\n    param1:\"" << plaintext.param1() << "\"\n    param2: " << plaintext.param2() << std::endl;

                std::string str_resp_plaintext = handle_plaintext(plaintext);
                std::string str_ciphertext(str_resp_plaintext.size(), '\0');

                uint8_t rand_iv[CRYPTO_AES_IV_LEN];
                uint8_t aes_tag[CRYPTO_AES_TAG_LEN];

                if (!crypto::rand_salt(rand_iv, CRYPTO_AES_IV_LEN))
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "random digit generation error.";
                    break;
                }

                ret = crypto::aes_encrypt((unsigned char *)str_resp_plaintext.data(), str_resp_plaintext.size(),
                                          s_client_key.aes_key, rand_iv, (unsigned char *)&str_ciphertext[0], aes_tag);
                if (!ret)
                {
                    status_code = oke::ResponseStatus_StatusCode_ERROR;
                    error_msg   = "data encryption error.";
                    break;
                }

                oke::Ciphertext *ciphertext = new oke::Ciphertext();

                ciphertext->set_cipher_version(CRYPTO_KEY_VERSION);
                ciphertext->set_aes_iv_12bytes(rand_iv, CRYPTO_AES_IV_LEN);
                ciphertext->set_aes_tag_16bytes(aes_tag, CRYPTO_AES_TAG_LEN);
                ciphertext->set_ciphertext_nbytes(std::move(str_ciphertext));

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

void run_server() {
    // Create a server that listens on port 7000, or whatever the user selected
    rpc::server srv("0.0.0.0", 7000);

    crypto::generate_ecdh_keys(s_server_key.ecdh_pub_key, s_server_key.ecdh_priv_key);

    srv.bind("key_exchange", &handle_key_exchange);

    srv.bind("ciphertext", &handle_ciphertext);

    // Run the server loop.
    srv.run();
}
