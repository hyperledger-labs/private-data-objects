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

#pragma once

#include <stdint.h>
#include <string>

#include "Types.h"

namespace ww
{
namespace crypto
{
    bool random_identifier(ww::types::ByteArray& identifier);

    bool b64_encode(
        const ww::types::ByteArray& message,
        std::string& encoded_message);

    bool b64_decode(
        const std::string& encoded_message,
        ww::types::ByteArray& message);

    bool crypto_hash(
        const ww::types::ByteArray& buffer,
        ww::types::ByteArray& hash);

    bool crypto_hmac(
        const ww::types::ByteArray& buffer,
        const ww::types::ByteArray& key,
        ww::types::ByteArray& hmac);

    bool crypto_pbkd(
        const std::string& password,
        const ww::types::ByteArray& salt,
        ww::types::ByteArray& key);

    namespace hash
    {
        bool sha256_hash(
            const ww::types::ByteArray& buffer,
            ww::types::ByteArray& hash);
        bool sha384_hash(
            const ww::types::ByteArray& buffer,
            ww::types::ByteArray& hash);
        bool sha512_hash(
            const ww::types::ByteArray& buffer,
            ww::types::ByteArray& hash);
        bool sha256_hmac(
            const ww::types::ByteArray& buffer,
            const ww::types::ByteArray& key,
            ww::types::ByteArray& hmac);
        bool sha384_hmac(
            const ww::types::ByteArray& buffer,
            const ww::types::ByteArray& key,
            ww::types::ByteArray& hmac);
        bool sha512_hmac(
            const ww::types::ByteArray& buffer,
            const ww::types::ByteArray& key,
            ww::types::ByteArray& hmac);
    };

    namespace aes
    {
        bool generate_key(ww::types::ByteArray& key);
        bool generate_iv(ww::types::ByteArray& iv);

        bool encrypt_message(
            const ww::types::ByteArray& message,
            const ww::types::ByteArray& key,
            const ww::types::ByteArray& iv,
            ww::types::ByteArray& encrypted_message);

        bool decrypt_message(
            const ww::types::ByteArray& message,
            const ww::types::ByteArray& key,
            const ww::types::ByteArray& iv,
            ww::types::ByteArray& encrypted_message);
    };

    namespace ecdsa
    {
        bool generate_keys(
            std::string& private_key,
            std::string& public_key);

        bool sign_message(
            const ww::types::ByteArray& message,
            const std::string& private_key,
            ww::types::ByteArray& signature);

        bool verify_signature(
            const ww::types::ByteArray& message,
            const std::string& public_key,
            const ww::types::ByteArray& signature);
    };

    namespace rsa
    {
        bool generate_keys(
            std::string& private_key,
            std::string& public_key);

        bool encrypt_message(
            const ww::types::ByteArray& message,
            const std::string& public_key,
            ww::types::ByteArray& encrypted_message);

        bool decrypt_message(
            const ww::types::ByteArray& message,
            const std::string& private_key,
            ww::types::ByteArray& encrypted_message);
    };
};                              /* namespace crypto */
};                              /* namespac ww */
