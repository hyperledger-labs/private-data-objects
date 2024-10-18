/*
 * Copyright 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "types/types.h"
#include <openssl/sha.h>

bool SHA256(const ByteArray& message, ByteArray& hash)
{
    SHA256_CTX c;
    hash.resize(32);
    SHA256_Init(&c);
    SHA256_Update(&c, message.data(), message.size());
    SHA256_Final(hash.data(),&c);
    return true;

err:
    return false;
}

