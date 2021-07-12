/* Copyright 2019 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#include <malloc.h>
#include <algorithm>
#include <stdint.h>
#include <string>

#include "Types.h"

#include "Cryptography.h"
#include "Util.h"
#include "WasmExtensions.h"

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::random_identifier
 * ----------------------------------------------------------------- */
bool ww::crypto::random_identifier(ww::types::ByteArray& identifier)
{
    if (identifier.size() == 0)
        identifier.resize(32);

    return ::random_identifier(identifier.size(), identifier.data());
}

static void verify_null_terminated(const char *data_pointer, size_t data_size)
{
    if (data_pointer[data_size - 1] != '\0')
    {
        CONTRACT_SAFE_LOG(3, "NOT NULL TERMINATED");
    }
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::b64_encode
 * ----------------------------------------------------------------- */
bool ww::crypto::b64_encode(
    const ww::types::ByteArray& message,
    std::string& encoded_message)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::b64_encode(message.data(), message.size(), (char**)&data_pointer, &data_size))
        return false;

    if (data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function b64_encode");
        return false;
    }

    encoded_message.clear();
    std::transform(data_pointer, data_pointer + data_size, std::back_inserter(encoded_message),
                   [](unsigned char c) -> char { return (char)c; });

    return true;
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::b64_decode(
    const std::string& encoded_message,
    ww::types::ByteArray& message)
{
    uint8_t *data_pointer = NULL;
    size_t data_size = 0;

    if (! ::b64_decode(encoded_message.c_str(), encoded_message.size(), &data_pointer, &data_size))
        return false;

    if (data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function b64_decode");
        return false;
    }

    return copy_internal_pointer(message, data_pointer, data_size);
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::aes::generate_key
 * ----------------------------------------------------------------- */
bool ww::crypto::aes::generate_key(ww::types::ByteArray& key)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::aes_generate_key(&data_pointer, &data_size))
        return false;

    if (data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function aes_generate_key");
        return false;
    }

    return copy_internal_pointer(key, data_pointer, data_size);
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::aes::generate_iv(ww::types::ByteArray& iv)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    ww::types::ByteArray identifier(32);
    if (! ww::crypto::random_identifier(identifier))
        return false;

    if (! ::aes_generate_iv(identifier.data(), identifier.size(), &data_pointer, &data_size))
        return false;

    if (data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function aes_generate_key");
        return false;
    }

    return copy_internal_pointer(iv, data_pointer, data_size);
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::aes::encrypt_message(
    const ww::types::ByteArray& message,
    const ww::types::ByteArray& key,
    const ww::types::ByteArray& iv,
    ww::types::ByteArray& cipher)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::aes_encrypt_message(
            message.data(), message.size(),
            key.data(), key.size(),
            iv.data(), iv.size(),
            &data_pointer, &data_size))
        return false;

    if (data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function aes_encrypt_message");
        return false;
    }

    return copy_internal_pointer(cipher, data_pointer, data_size);
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::aes::decrypt_message(
    const ww::types::ByteArray& cipher,
    const ww::types::ByteArray& key,
    const ww::types::ByteArray& iv,
    ww::types::ByteArray& message)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::aes_decrypt_message(
            cipher.data(), cipher.size(),
            key.data(), key.size(),
            iv.data(), iv.size(),
            &data_pointer, &data_size))
        return false;

    if (data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function aes_decrypt_message");
        return false;
    }

    return copy_internal_pointer(message, data_pointer, data_size);
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::ecdsa::generate_keys(
    std::string& private_key,
    std::string& public_key)
{
    uint8_t* priv_data_pointer = NULL;
    size_t priv_data_size = 0;

    uint8_t* pub_data_pointer = NULL;
    size_t pub_data_size = 0;

    if (! ::ecdsa_create_signing_keys(
            (char**)&priv_data_pointer, &priv_data_size,
            (char**)&pub_data_pointer, &pub_data_size))
        return false;

    if (priv_data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function ecdsa_create_signing_keys");
        return false;
    }
    private_key.assign((const char*)priv_data_pointer, priv_data_size - 1); // strip the null character

    if (pub_data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function ecdsa_create_signing_keys");
        return false;
    }
    public_key.assign((const char*)pub_data_pointer, pub_data_size - 1); // string the null character

    return true;
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::ecdsa::sign_message(
    const ww::types::ByteArray& message,
    const std::string& private_key,
    ww::types::ByteArray& signature)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::ecdsa_sign_message(
            message.data(), message.size(),
            private_key.c_str(), private_key.size(),
            &data_pointer, &data_size))
        return false;

    if (data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function ecdsa_sign_message");
        return false;
    }

    return copy_internal_pointer(signature, data_pointer, data_size);
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::ecdsa::verify_signature(
    const ww::types::ByteArray& message,
    const std::string& public_key,
    const ww::types::ByteArray& signature)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    return ::ecdsa_verify_signature(
        message.data(), message.size(),
        public_key.c_str(), public_key.size(),
        signature.data(), signature.size());
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::rsa::generate_keys(
    std::string& private_key,
    std::string& public_key)
{
    uint8_t* priv_data_pointer = NULL;
    size_t priv_data_size = 0;

    uint8_t* pub_data_pointer = NULL;
    size_t pub_data_size = 0;

    if (! ::rsa_generate_keys(
            (char**)&priv_data_pointer, &priv_data_size,
            (char**)&pub_data_pointer, &pub_data_size))
        return false;

    // there is a possibility that allocated memory would not be freed using the
    // logic below (e.g. if the copy_internal_pointer fails); i don't believe this
    // can be address well until exceptions are fully supported by WASM

    if (priv_data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function rsa_generate_keys");
        return false;
    }
    private_key.assign((const char*)priv_data_pointer, priv_data_size - 1); // strip null

    if (pub_data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function rsa_generate_keys");
        return false;
    }
    public_key.assign((const char*)pub_data_pointer, pub_data_size - 1); // strip null

    return true;
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::rsa::encrypt_message(
    const ww::types::ByteArray& message,
    const std::string& public_key,
    ww::types::ByteArray& cipher)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::rsa_encrypt_message(
            message.data(), message.size(),
            public_key.c_str(), public_key.size(),
            &data_pointer, &data_size))
        return false;

    if (data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function rsa_encrypt_message");
        return false;
    }

    return copy_internal_pointer(cipher, data_pointer, data_size);
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::rsa::decrypt_message(
    const ww::types::ByteArray& cipher,
    const std::string& private_key,
    ww::types::ByteArray& message)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::rsa_decrypt_message(
            cipher.data(), cipher.size(),
            private_key.c_str(), private_key.size(),
            &data_pointer, &data_size))
        return false;

    if (data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function rsa_decrypt_message");
        return false;
    }

    return copy_internal_pointer(message, data_pointer, data_size);
}
