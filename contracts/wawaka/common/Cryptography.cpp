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

#include <malloc.h>
#include <stdint.h>
#include <string.h>

#include "Cryptography.h"
#include "StringArray.h"
#include "Util.h"
#include "WasmExtensions.h"

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::random_identifier
 * ----------------------------------------------------------------- */
bool ww::crypto::random_identifier(StringArray& identifier)
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
    const StringArray& message,
    StringArray& encoded_message)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::b64_encode(message.c_data(), message.size(), (char**)&data_pointer, &data_size))
        return false;

    if (data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function b64_encode");
        return false;
    }

    verify_null_terminated((const char*)data_pointer, data_size);
    return copy_internal_pointer(encoded_message, data_pointer, data_size);
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::b64_decode(
    const StringArray& encoded_message,
    StringArray& message)
{
    uint8_t *data_pointer = NULL;
    size_t data_size = 0;

    verify_null_terminated((const char*)encoded_message.c_data(), encoded_message.size());

    if (! ::b64_decode((const char*)encoded_message.c_data(), encoded_message.size(), &data_pointer, &data_size))
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
bool ww::crypto::aes::generate_key(StringArray& key)
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
bool ww::crypto::aes::generate_iv(StringArray& iv)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    StringArray identifier(32);
    if (! ww::crypto::random_identifier(identifier))
        return false;

    if (! ::aes_generate_iv(identifier.c_data(), identifier.size(), &data_pointer, &data_size))
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
    const StringArray& message,
    const StringArray& key,
    const StringArray& iv,
    StringArray& cipher)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::aes_encrypt_message(
            message.c_data(), message.size(),
            key.c_data(), key.size(),
            iv.c_data(), iv.size(),
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
    const StringArray& cipher,
    const StringArray& key,
    const StringArray& iv,
    StringArray& message)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::aes_decrypt_message(
            cipher.c_data(), cipher.size(),
            key.c_data(), key.size(),
            iv.c_data(), iv.size(),
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
    StringArray& private_key,
    StringArray& public_key)
{
    uint8_t* priv_data_pointer = NULL;
    size_t priv_data_size = 0;

    uint8_t* pub_data_pointer = NULL;
    size_t pub_data_size = 0;

    if (! ::ecdsa_create_signing_keys(
            (char**)&priv_data_pointer, &priv_data_size,
            (char**)&pub_data_pointer, &pub_data_size))
        return false;

    // there is a possibility that allocated memory would not be freed using the
    // logic below (e.g. if the copy_internal_pointer fails); i don't believe this
    // can be address well until exceptions are fully supported by WASM

    if (priv_data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function ecdsa_create_signing_keys");
        return false;
    }

    verify_null_terminated((const char*)priv_data_pointer, priv_data_size);

    if (! copy_internal_pointer(private_key, priv_data_pointer, priv_data_size))
        return false;

    if (pub_data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function ecdsa_create_signing_keys");
        return false;
    }

    verify_null_terminated((const char*)pub_data_pointer, pub_data_size);

    return copy_internal_pointer(public_key, pub_data_pointer, pub_data_size);
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::ecdsa::sign_message(
    const StringArray& message,
    const StringArray& private_key,
    StringArray& signature)
{
    verify_null_terminated((const char*)private_key.c_data(), private_key.size());

    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::ecdsa_sign_message(
            message.c_data(), message.size(),
            (const char*)private_key.c_data(), private_key.size(),
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
    const StringArray& message,
    const StringArray& public_key,
    const StringArray& signature)
{
    verify_null_terminated((const char*)public_key.c_data(), public_key.size());

    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    return ::ecdsa_verify_signature(
        message.c_data(), message.size(),
        (const char*)public_key.c_data(), public_key.size(),
        signature.c_data(), signature.size());
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::rsa::generate_keys(
    StringArray& private_key,
    StringArray& public_key)
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

    if (! copy_internal_pointer(private_key, priv_data_pointer, priv_data_size))
        return false;

    if (pub_data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function rsa_generate_keys");
        return false;
    }

    return copy_internal_pointer(public_key, pub_data_pointer, pub_data_size);
}

/* ----------------------------------------------------------------- *
 * NAME: ww::crypto::
 * ----------------------------------------------------------------- */
bool ww::crypto::rsa::encrypt_message(
    const StringArray& message,
    const StringArray& public_key,
    StringArray& cipher)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::rsa_encrypt_message(
            message.c_data(), message.size(),
            (const char*)public_key.c_data(), public_key.size(),
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
    const StringArray& cipher,
    const StringArray& private_key,
    StringArray& message)
{
    uint8_t* data_pointer = NULL;
    size_t data_size = 0;

    if (! ::rsa_decrypt_message(
            cipher.c_data(), cipher.size(),
            (const char*)private_key.c_data(), private_key.size(),
            &data_pointer, &data_size))
        return false;

    if (data_pointer == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function rsa_decrypt_message");
        return false;
    }

    return copy_internal_pointer(message, data_pointer, data_size);
}
