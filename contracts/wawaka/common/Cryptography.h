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
#include <string.h>

#include "Types.h"

namespace ww
{
namespace crypto
{
    bool random_identifier(ww::types::ByteArray& identifier);

    bool b64_encode(
        const ww::types::ByteArray& message,
        ww::types::ByteArray& encoded_message);

    bool b64_decode(
        const ww::types::ByteArray& encoded_message,
        ww::types::ByteArray& message);

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
            ww::types::ByteArray& private_key,
            ww::types::ByteArray& public_key);

        bool sign_message(
            const ww::types::ByteArray& message,
            const ww::types::ByteArray& private_key,
            ww::types::ByteArray& signature);

        bool verify_signature(
            const ww::types::ByteArray& message,
            const ww::types::ByteArray& public_key,
            const ww::types::ByteArray& signature);
    };

    namespace rsa
    {
        bool generate_keys(
            ww::types::ByteArray& private_key,
            ww::types::ByteArray& public_key);

        bool encrypt_message(
            const ww::types::ByteArray& message,
            const ww::types::ByteArray& public_key,
            ww::types::ByteArray& encrypted_message);

        bool decrypt_message(
            const ww::types::ByteArray& message,
            const ww::types::ByteArray& private_key,
            ww::types::ByteArray& encrypted_message);
    };
};                              /* namespace crypto */
};                              /* namespac ww */
