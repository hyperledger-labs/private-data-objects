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
#include "hash.h"
#include <openssl/sha.h>
/***Conditional compile untrusted/trusted***/
#if _UNTRUSTED_
#include <openssl/crypto.h>
#include <stdio.h>
#else
#include "tSgxSSL_api.h"
#endif
/***END Conditional compile untrusted/trusted***/

namespace pcrypto = pdo::crypto;

// Compute SHA256 digest
void pcrypto::SHA256Hash(
    const unsigned char* buf, unsigned int buf_size, unsigned char hash[])
{
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, buf, buf_size);
    SHA256_Final(hash, &sha);
}

// Compute SHA384 digest
void pcrypto::SHA384Hash(
    const unsigned char* buf, unsigned int buf_size, unsigned char hash[])
{
    SHA512_CTX sha;
    SHA384_Init(&sha);
    SHA384_Update(&sha, buf, buf_size);
    SHA384_Final(hash, &sha);
}

