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

#include "Cryptography.h"
#include "Secret.h"
#include "Util.h"
#include "Value.h"

#include "WasmExtensions.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: send_secret
//
// returns a JSON encoded object:
//
// {
//    "encrypted_session_key": <base64 encoded encrypted session key>
//    "session_key_iv": <base64 encoded AES IV>
//    "encrypted_message": <base64 encode encrypted message>
// }
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ww::secret::send_secret(
    const std::string& encryption_key,
    const std::string& message_string,
    std::string& encrypted_message_string)
{
    ww::value::Object secret_object;
    if (! send_secret(encryption_key, message_string, secret_object))
    {
        CONTRACT_SAFE_LOG(3, "failed to encrypt secret");
        return false;
    }

    if (! secret_object.serialize(encrypted_message_string))
    {
        CONTRACT_SAFE_LOG(3, "failed to serialize message");
        return false;
    }

    return true;
}

bool ww::secret::send_secret(
    const std::string& encryption_key,
    const std::string& message_string,
    ww::value::Object& secret_object)
{
    // ---------- encrypt message ----------
    ww::types::ByteArray iv;
    ww::types::ByteArray session_key;
    if (! ww::crypto::aes::generate_key(session_key) || ! ww::crypto::aes::generate_iv(iv))
    {
        CONTRACT_SAFE_LOG(3, "failed to generate session key");
        return false;
    }

    ww::types::ByteArray message(message_string.begin(), message_string.end());
    ww::types::ByteArray cipher;
    if (! ww::crypto::aes::encrypt_message(message, session_key, iv, cipher))
    {
        CONTRACT_SAFE_LOG(3, "failed to encrypt the secret");
        return false;
    }

    std::string encoded_cipher;
    if (! ww::crypto::b64_encode(cipher, encoded_cipher))
    {
        CONTRACT_SAFE_LOG(3, "failed to encode cipher text");
        return false;
    }

    // ---------- encrypt the session key ----------
    ww::types::ByteArray encrypted_session_key;
    if (! ww::crypto::rsa::encrypt_message(session_key, encryption_key, encrypted_session_key))
    {
        CONTRACT_SAFE_LOG(3, "failed to encrypt session key");
        return false;
    }

    std::string encoded_session_key;
    if (! ww::crypto::b64_encode(encrypted_session_key, encoded_session_key))
    {
        CONTRACT_SAFE_LOG(3, "failed to encode session key");
        return false;
    }

    // ---------- encode the IV ----------
    std::string encoded_iv;
    if (! ww::crypto::b64_encode(iv, encoded_iv))
    {
        CONTRACT_SAFE_LOG(3, "failed to encode session key");
        return false;
    }

    // ---------- build the object ----------
    secret_object.set_string("encrypted_session_key", encoded_session_key.c_str());
    secret_object.set_string("session_key_iv", encoded_iv.c_str());
    secret_object.set_string("encrypted_message", encoded_cipher.c_str());

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: recv_secret
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ww::secret::recv_secret(
    const std::string& decryption_key,
    const std::string& encrypted_message_string,
    std::string& message_string)
{
    ww::value::Object secret_object;
    if (! secret_object.deserialize(encrypted_message_string.c_str()))
    {
        CONTRACT_SAFE_LOG(3, "failed to deserialize secret");
        return false;
    }

    return ww::secret::recv_secret(decryption_key, secret_object, message_string);
}

bool ww::secret::recv_secret(
    const std::string& decryption_key,
    const ww::value::Object& secret_object,
    std::string& message_string)
{
    if (! secret_object.validate_schema(CONTRACT_SECRET_SCHEMA))
    {
        CONTRACT_SAFE_LOG(3, "invalid secret");
        return false;
    }

    const std::string encoded_session_key(secret_object.get_string("encrypted_session_key"));
    const std::string encoded_iv(secret_object.get_string("session_key_iv"));
    const std::string encoded_cipher(secret_object.get_string("encrypted_message"));

    ww::types::ByteArray iv;
    if (! ww::crypto::b64_decode(encoded_iv, iv))
    {
        CONTRACT_SAFE_LOG(3, "failed to decode session iv");
        return false;
    }

    ww::types::ByteArray encrypted_session_key;
    if (! ww::crypto::b64_decode(encoded_session_key, encrypted_session_key))
    {
        CONTRACT_SAFE_LOG(3, "failed to decode session key");
        return false;
    }

    ww::types::ByteArray session_key;
    if (! ww::crypto::rsa::decrypt_message(encrypted_session_key, decryption_key, session_key))
    {
        CONTRACT_SAFE_LOG(3, "failed to decrypt session key");
        return false;
    }

    ww::types::ByteArray cipher;
    if (! ww::crypto::b64_decode(encoded_cipher, cipher))
    {
        CONTRACT_SAFE_LOG(3, "failed to decode cipher");
        return false;
    }

    ww::types::ByteArray message;
    if (! ww::crypto::aes::decrypt_message(cipher, session_key, iv, message))
    {
        CONTRACT_SAFE_LOG(3, "failed to decrypt cipher");
        return false;
    }

    message_string = ww::types::ByteArrayToString(message);
    return true;
}
