/* Copyright 2022 Intel Corporation
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

#include "types.h"

namespace pdo
{
namespace crypto
{
    const unsigned int PBDK_Iterations = 10000;

    void SHA256Hash(const ByteArray& message, ByteArray& hash);
    void SHA256HMAC(const ByteArray& message, const ByteArray& key, ByteArray& hmac);

    void SHA384Hash(const ByteArray& message, ByteArray& hash);
    void SHA384HMAC(const ByteArray& message, const ByteArray& key, ByteArray& hmac);

    void SHA512Hash(const ByteArray& message, ByteArray& hash);
    void SHA512HMAC(const ByteArray& message, const ByteArray& key, ByteArray& hmac);

    void SHA512PasswordBasedKeyDerivation(const std::string& password, const ByteArray& salt, ByteArray& hmac);

    // these default to the sha256 hash functions
    ByteArray ComputeMessageHash(const ByteArray& message);
    ByteArray ComputeMessageHMAC(const ByteArray& key, const ByteArray& message);
    ByteArray ComputePasswordBasedKeyDerivation(const std::string& password, const ByteArray& salt);
}
}
