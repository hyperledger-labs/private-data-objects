/* Copyright 2018 Intel Corporation
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
#include "crypto_utils.h"
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <algorithm>
#include <memory>
#include <vector>
#include "base64.h"  //simple base64 enc/dec routines
#include "crypto_shared.h"
#include "error.h"
#include "hex_string.h"
/***Conditional compile untrusted/trusted***/
#if _UNTRUSTED_
#include <openssl/crypto.h>
#include <stdio.h>
#else
#include "tSgxSSL_api.h"
#endif
/***END Conditional compile untrusted/trusted***/

namespace pcrypto = pdo::crypto;
namespace constants = pdo::crypto::constants;

// Error handling
namespace Error = pdo::error;

//***Private functions***//

// Compute SHA256 digest
static void SHA256Hash(
    const unsigned char* buf, int buf_size, unsigned char hash[SHA256_DIGEST_LENGTH])
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, buf, buf_size);
    SHA256_Final(hash, &sha256);
}  // pcrypto::SHA256Hash

// Compute SHA256 HMAC
static void SHA256HMAC(
    const unsigned char* buf, int buf_size, const unsigned char* key, unsigned int key_len,
    unsigned char *hmac, unsigned int hmac_len)
{
    Error::ThrowIfNull(buf, "null buffer");
    Error::ThrowIfNull(key, "null key");
    Error::ThrowIfNull(hmac, "null hmac buffer");

    HMAC_CTX* hmac_ctx = HMAC_CTX_new();
    Error::ThrowIfNull(hmac_ctx, "invalid hmac context");

    try
    {
        int ret;
        ret = HMAC_Init_ex(hmac_ctx, key, key_len, EVP_sha256(), NULL);
        Error::ThrowIf<Error::RuntimeError>(ret == 0, "hmac init failed");

        ret = HMAC_Update(hmac_ctx, buf, buf_size);
        Error::ThrowIf<Error::RuntimeError>(ret == 0, "hmac update failed");

        ret = HMAC_Final(hmac_ctx, hmac, &hmac_len);
        Error::ThrowIf<Error::RuntimeError>(ret == 0, "hmac final failed");
    }
    catch(...)
    {
        HMAC_CTX_free(hmac_ctx);
        throw;
    }

    HMAC_CTX_free(hmac_ctx);
}  // pcrypto::SHA256HMAC

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Generate cryptographically strong random bimsging
// throws: RuntimeError
ByteArray pcrypto::RandomBitString(size_t length)
{
    char err[constants::ERR_BUF_LEN];
    ByteArray buf(length);
    int res = 0;

    if (length < 1)
    {
        std::string msg("Crypto Error (RandomBitString): length argument must be at least 1");
        throw Error::ValueError(msg);
    }

    res = RAND_bytes(buf.data(), length);

    if (res != 1)
    {
        std::string msg("Crypto Error (RandomBitString): ");
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        msg += err;
        throw Error::RuntimeError(msg);
    }

    return buf;
}  // pcrypto::RandomBitString

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Compute SHA256 hash of message.data()
// returns ByteArray containing raw binary data
ByteArray pcrypto::ComputeMessageHash(const ByteArray& message)
{
    ByteArray hash(SHA256_DIGEST_LENGTH);
    SHA256Hash((const unsigned char*)message.data(), message.size(), hash.data());
    return hash;
}  // pcrypto::ComputeMessageHash

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Compute SHA256-based HMAC of message.data()
// returns ByteArray containing raw binary data
ByteArray pcrypto::ComputeMessageHMAC(const ByteArray& key, const ByteArray& message)
{
    ByteArray hmac(SHA256_DIGEST_LENGTH);
    SHA256HMAC(message.data(), message.size(), key.data(), key.size(), hmac.data(), hmac.size());
    return hmac;
}  // pcrypto::ComputeMessageHMAC
