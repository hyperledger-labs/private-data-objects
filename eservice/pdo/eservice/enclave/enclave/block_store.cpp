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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <bits/stdc++.h>

#include "pdo_error.h"
#include "error.h"
#include "log.h"
#include "types.h"
#include "hex_string.h"

#include "enclave/base.h"
#include "enclave/block_store.h"

static std::unordered_map<std::string, std::string> map;
static pthread_spinlock_t lock;

pdo_err_t pdo::enclave_api::block_store::BlockStoreInit() {
    int ret;

    ret = pthread_spin_init(&lock, PTHREAD_PROCESS_SHARED);
    if (ret != 0) {
        Log(PDO_LOG_DEBUG, "Failed to init block store spinlock: %d", ret);
        return PDO_ERR_SYSTEM;
    }

    return PDO_SUCCESS;
}

int pdo::enclave_api::block_store::BlockStoreGet(
    const uint8_t* key,
    const size_t keySize,
    uint8_t **value,
    size_t* valueSize
    )
{
    int result = 0;
    std::string keyStr = BinaryToHexString(key, keySize);
    Log(PDO_LOG_DEBUG, "Block Store Get: '%s'", keyStr.c_str());

    // **********
    // LOCK
    pthread_spin_lock(&lock);

    if (map.find(keyStr) == map.end()) {
        Log(PDO_LOG_DEBUG, "Failed to find key in block store map: '%s'",
            keyStr.c_str());
        *valueSize = 0;
        *value = NULL;
        result = PDO_ERR_VALUE;
        goto done;
    } else {
        std::string valueStr = map[keyStr];
        Log(PDO_LOG_DEBUG, "Block Store found key: '%s' -> '%s'",
            keyStr.c_str(), valueStr.c_str());

        /*
         * TODO - This leaks memory! There is nothing to clean up this
         * allocated data later
         */
        *valueSize = valueStr.size() / 2;
        *value = (uint8_t *)malloc(*valueSize);
        if (!*value) {
            Log(PDO_LOG_ERROR,
                "Failed to allocate %zu bytes for get return value.",
                *valueSize);
            *valueSize = 0;
            result = PDO_ERR_MEMORY;
            goto done;
        }

        // Deserialize the data from the cache into the buffer
        HexStringToBinary(*value, *valueSize, valueStr);

        result = PDO_SUCCESS;
    }

done:
    pthread_spin_unlock(&lock);
    // UNLOCK
    // **********

    return result;
}

int pdo::enclave_api::block_store::BlockStorePut(
    const uint8_t* key,
    const size_t keySize,
    const uint8_t* value,
    const size_t valueSize
    )
{
    std::string keyStr = BinaryToHexString(key, keySize);
    std::string valueStr = BinaryToHexString(value, valueSize);

    Log(PDO_LOG_DEBUG, "Block Store Put: %zu bytes '%s' -> %zu bytes '%s'",
        keySize, keyStr.c_str(), valueSize, valueStr.c_str());
    // **********
    // LOCK
    pthread_spin_lock(&lock);

    map[keyStr] = valueStr;

    pthread_spin_unlock(&lock);
    // UNLOCK
    // **********

    return PDO_SUCCESS;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int pdo::enclave_api::block_store::BlockStoreHead(
    const ByteArray& inKey
    )
{
    uint8_t *value;
    size_t value_size;

    // Fetch the state from the block storage
    int ret = BlockStoreGet(inKey.data(), inKey.size(),
                            &value, &value_size);
    if (ret != 0) {
        // No data found - return -1 for size
        return -1;
    }

    // Found data - return its size
    return (int)value_size;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::block_store::BlockStoreGet(
    const ByteArray& inKey,
    ByteArray& outValue
    )
{
    pdo_err_t result = PDO_SUCCESS;

    uint8_t *value;
    size_t value_size;

    // Fetch the state from the block storage
    int ret = BlockStoreGet(inKey.data(), inKey.size(),
                            &value, &value_size);
    pdo::error::ThrowIf<pdo::error::ValueError>(
       ret != 0, "Unable to get from Block Store");

    // Copy the buffer back to the caller's ByteArray
    outValue.resize(value_size);
    outValue.assign(value, value + value_size);

    return result;
}


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::block_store::BlockStorePut(
    const ByteArray& inKey,
    const ByteArray& inValue
    )
{
    pdo_err_t result = PDO_SUCCESS;

    int ret = BlockStorePut(inKey.data(), inKey.size(),
                            inValue.data(), inValue.size());

    pdo::error::ThrowIf<pdo::error::ValueError>(
       ret != 0, "Unable to put into the Block Store");

    return result;
}
