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

#include "StringArray.h"

namespace ww
{
namespace crypto
{
    bool random_identifier(StringArray& identifier);

    bool b64_encode(
        const StringArray& message,
        StringArray& encoded_message);

    bool b64_decode(
        const StringArray& encoded_message,
        StringArray& message);

    namespace aes
    {
        bool generate_key(StringArray& key);
        bool generate_iv(StringArray& iv);

        bool encrypt_message(
            const StringArray& message,
            const StringArray& key,
            const StringArray& iv,
            StringArray& encrypted_message);

        bool decrypt_message(
            const StringArray& message,
            const StringArray& key,
            const StringArray& iv,
            StringArray& encrypted_message);
    };

    namespace ecdsa
    {
        bool generate_keys(
            StringArray& private_key,
            StringArray& public_key);

        bool sign_message(
            const StringArray& message,
            const StringArray& private_key,
            StringArray& signature);

        bool verify_signature(
            const StringArray& message,
            const StringArray& public_key,
            const StringArray& signature);
    };

    namespace rsa
    {
        bool generate_keys(
            StringArray& private_key,
            StringArray& public_key);

        bool encrypt_message(
            const StringArray& message,
            const StringArray& public_key,
            StringArray& encrypted_message);

        bool decrypt_message(
            const StringArray& message,
            const StringArray& private_key,
            StringArray& encrypted_message);
    };
};                              /* namespace crypto */
};                              /* namespac ww */
