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
static void _ComputeHash_(
    const EVP_MD *hashfunc(void),
    const ByteArray& message,
    ByteArray& hash)
{
    const EVP_MD *md = hashfunc();
    hash.resize(EVP_MD_size(md));

    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> evp_md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    pdo::error::ThrowIfNull(evp_md_ctx.get(), "invalid hash context");

    int ret;
    ret = EVP_DigestInit_ex(evp_md_ctx.get(), md, NULL);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(ret == 0, "hash init failed");

    ret = EVP_DigestUpdate(evp_md_ctx.get(), message.data(), message.size());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(ret == 0, "hash update failed");

    ret = EVP_DigestFinal_ex(evp_md_ctx.get(), hash.data(), NULL);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(ret == 0, "hash final failed");
}

void pcrypto::SHA256Hash(const ByteArray& message, ByteArray& hash)
{
    _ComputeHash_(EVP_sha256, message, hash);
}

void pcrypto::SHA384Hash(const ByteArray& message, ByteArray& hash)
{
    _ComputeHash_(EVP_sha384, message, hash);
}

void pcrypto::SHA512Hash(const ByteArray& message, ByteArray& hash)
{
    _ComputeHash_(EVP_sha512, message, hash);
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
    const EVP_MD *md = hashfunc();
    hmac.resize(EVP_MD_size(md));

    std::unique_ptr<HMAC_CTX, void (*)(HMAC_CTX*)> hmac_ctx(HMAC_CTX_new(), HMAC_CTX_free);
    pdo::error::ThrowIfNull(hmac_ctx.get(), "invalid hmac context");

    int ret;
    ret = HMAC_Init_ex(hmac_ctx.get(), key.data(), key.size(), md, NULL);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(ret == 0, "hmac init failed");

    ret = HMAC_Update(hmac_ctx.get(), message.data(), message.size());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(ret == 0, "hmac update failed");

    ret = HMAC_Final(hmac_ctx.get(), hmac.data(), NULL);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(ret == 0, "hmac final failed");
}

void pcrypto::SHA256HMAC(
    const ByteArray& message,
    const ByteArray& key,
    ByteArray& hmac)
{
    _ComputeHMAC_(EVP_sha256, message, key, hmac);
}

void pcrypto::SHA384HMAC(
    const ByteArray& message,
    const ByteArray& key,
    ByteArray& hmac)
{
    _ComputeHMAC_(EVP_sha384, message, key, hmac);
}

void pcrypto::SHA512HMAC(
    const ByteArray& message,
    const ByteArray& key,
    ByteArray& hmac)
{
    _ComputeHMAC_(EVP_sha512, message, key, hmac);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
//
static void _ComputePasswordBasedKeyDerivation_(
    const EVP_MD *hashfunc(void),
    const std::string& password,
    const ByteArray& salt,
    const unsigned int iterations,
    ByteArray& key)
{
    const EVP_MD *md = hashfunc();
    key.resize(EVP_MD_size(md));

    int ret;
    ret = PKCS5_PBKDF2_HMAC(
        password.c_str(), password.size(),
        salt.data(), salt.size(),
        iterations, md,
        key.size(), key.data());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(ret == 0, "password derivation failed");
}

void pcrypto::SHA512PasswordBasedKeyDerivation(
    const std::string& password,
    const ByteArray& salt,
    ByteArray& key)
{
    _ComputePasswordBasedKeyDerivation_(EVP_sha512, password, salt, pcrypto::PBDK_Iterations, key);
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

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Derive key from password and salt using SHA512
// returns ByteArray containing raw binary data
ByteArray pcrypto::ComputePasswordBasedKeyDerivation(
    const std::string& password,
    const ByteArray& salt)
{
    ByteArray key;
    pcrypto::SHA512PasswordBasedKeyDerivation(password, salt, key);
    return key;
}
