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

#pragma once

#include <memory>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>

namespace pdo
{
namespace crypto
{
    namespace constants
    {
        // OpenSSL Error string buffer size
        const int ERR_BUF_LEN = 130;
    }

    // Typedefs for memory management
    // Specify type and destroy function type for unique_ptrs
    typedef std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> BIGNUM_ptr;
    typedef std::unique_ptr<BN_CTX, void (*)(BN_CTX*)> BN_CTX_ptr;

    typedef std::unique_ptr<BIO, void (*)(BIO*)> BIO_ptr;

    typedef std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)> CTX_ptr;

    typedef std::unique_ptr<EC_GROUP, void (*)(EC_GROUP*)> EC_GROUP_ptr;
    typedef std::unique_ptr<EC_KEY, void (*)(EC_KEY*)> EC_KEY_ptr;
    typedef std::unique_ptr<EC_POINT, void (*)(EC_POINT*)> EC_POINT_ptr;
    typedef std::unique_ptr<ECDSA_SIG, void (*)(ECDSA_SIG*)> ECDSA_SIG_ptr;

    typedef std::unique_ptr<RSA, void (*)(RSA*)> RSA_ptr;
}
}
