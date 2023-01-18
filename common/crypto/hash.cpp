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

#include "error.h"
#include "hash.h"
#include <memory>
#include <openssl/sha.h>
#include <openssl/hmac.h>

/***Conditional compile untrusted/trusted***/
#if _UNTRUSTED_
#include <openssl/crypto.h>
#include <stdio.h>
#else
#include "tSgxSSL_api.h"
#endif
/***END Conditional compile untrusted/trusted***/

namespace pcrypto = pdo::crypto;

// -----------------------------------------------------------------
// Hash Functions
// -----------------------------------------------------------------

void pcrypto::SHA256Hash(const ByteArray& message, ByteArray& hash)
{
    hash.resize(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, message.data(), message.size());
    SHA256_Final(hash.data(), &sha);
}

void pcrypto::SHA384Hash(const ByteArray& message, ByteArray& hash)
{
    hash.resize(SHA384_DIGEST_LENGTH);

    SHA512_CTX sha;
    SHA384_Init(&sha);
    SHA384_Update(&sha, message.data(), message.size());
    SHA384_Final(hash.data(), &sha);
}

void pcrypto::SHA512Hash(const ByteArray& message, ByteArray& hash)
{
    hash.resize(SHA512_DIGEST_LENGTH);

    SHA512_CTX sha;
    SHA512_Init(&sha);
    SHA512_Update(&sha, message.data(), message.size());
    SHA512_Final(hash.data(), &sha);
}

// -----------------------------------------------------------------
// HMAC Functions
// -----------------------------------------------------------------

static void _ComputeHMAC_(
    const EVP_MD *hashfunc(void),
    const ByteArray& message,
    const ByteArray& key,
    ByteArray& hmac)
{
    HMAC_CTX* hmac_ctx = HMAC_CTX_new();
    pdo::error::ThrowIfNull(hmac_ctx, "invalid hmac context");

    try
    {
        int ret;
        ret = HMAC_Init_ex(hmac_ctx, key.data(), key.size(), hashfunc(), NULL);
        pdo::error::ThrowIf<pdo::error::RuntimeError>(ret == 0, "hmac init failed");

        ret = HMAC_Update(hmac_ctx, message.data(), message.size());
        pdo::error::ThrowIf<pdo::error::RuntimeError>(ret == 0, "hmac update failed");

        ret = HMAC_Final(hmac_ctx, hmac.data(), NULL);
        pdo::error::ThrowIf<pdo::error::RuntimeError>(ret == 0, "hmac final failed");
    }
    catch(...)
    {
        HMAC_CTX_free(hmac_ctx);
        throw;
    }

    HMAC_CTX_free(hmac_ctx);
}

void pcrypto::SHA256HMAC(
    const ByteArray& message,
    const ByteArray& key,
    ByteArray& hmac)
{
    hmac.resize(SHA256_DIGEST_LENGTH);
    _ComputeHMAC_(EVP_sha256, message, key, hmac);
}

void pcrypto::SHA384HMAC(
    const ByteArray& message,
    const ByteArray& key,
    ByteArray& hmac)
{
    hmac.resize(SHA384_DIGEST_LENGTH);
    _ComputeHMAC_(EVP_sha384, message, key, hmac);
}

void pcrypto::SHA512HMAC(
    const ByteArray& message,
    const ByteArray& key,
    ByteArray& hmac)
{
    hmac.resize(SHA512_DIGEST_LENGTH);
    _ComputeHMAC_(EVP_sha512, message, key, hmac);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Compute SHA256 hash of message.data()
// returns ByteArray containing raw binary data
ByteArray pcrypto::ComputeMessageHash(const ByteArray& message)
{
    ByteArray hash(SHA256_DIGEST_LENGTH);
    pcrypto::SHA256Hash(message, hash);
    return hash;
}  // pcrypto::ComputeMessageHash

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Compute SHA256-based HMAC of message.data()
// returns ByteArray containing raw binary data
ByteArray pcrypto::ComputeMessageHMAC(const ByteArray& key, const ByteArray& message)
{
    ByteArray hmac;
    pcrypto::SHA256HMAC(message, key, hmac);
    return hmac;
}  // pcrypto::ComputeMessageHMAC
