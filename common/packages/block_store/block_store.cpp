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

#include <bits/stdc++.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "error.h"
#include "hex_string.h"
#include "pdo_error.h"
#include "types.h"

#include "block_store.h"

namespace pdo
{
    extern void Log(pdo_log_level_t logLevel, const char* message, ...);
}

// TODO:
// Very simple implementation that should be improved later
// (likely implementation moved into a dedicated database)
static std::unordered_map<std::string, std::string> map;
static pthread_spinlock_t lock;

pdo_err_t pdo::block_store::BlockStoreInit()
{
    int ret;

    ret = pthread_spin_init(&lock, PTHREAD_PROCESS_SHARED);
    if (ret != 0)
    {
        Log(PDO_LOG_DEBUG, "Failed to init block store spinlock: %d", ret);
        return PDO_ERR_SYSTEM;
    }

    return PDO_SUCCESS;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStoreHead(
    const uint8_t* inId,
    const size_t inIdSize,
    bool* outIsPresent,
    size_t* outValueSize
)
{
    std::string keyStr = BinaryToHexString(inId, inIdSize);
    Log(PDO_LOG_DEBUG, "BlockStoreHead: '%s'", keyStr.c_str());

    // **********
    // LOCK
    pthread_spin_lock(&lock);

    if (map.find(keyStr) == map.end())
    {
        Log(PDO_LOG_DEBUG, "Failed to find key in block store map: '%s'", keyStr.c_str());
        *outIsPresent = false;
    }
    else
    {
        std::string valueStr = map[keyStr];
        Log(PDO_LOG_DEBUG, "Block store found key: '%s' -> '%s'", keyStr.c_str(), valueStr.c_str());

        *outIsPresent = true;
        *outValueSize = valueStr.size() / 2;
    }

    pthread_spin_unlock(&lock);
    // UNLOCK
    // **********

    return PDO_SUCCESS;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStoreGet(
    const uint8_t* inId,
    const size_t inIdSize,
    uint8_t* outValue,
    const size_t inValueSize
)
{
    pdo_err_t result = PDO_SUCCESS;
    std::string keyStr = BinaryToHexString(inId, inIdSize);
    Log(PDO_LOG_DEBUG, "Block store get: '%s'", keyStr.c_str());

    // **********
    // LOCK
    pthread_spin_lock(&lock);

    if (map.find(keyStr) == map.end())
    {
        Log(PDO_LOG_DEBUG, "Failed to find key in block store map: '%s'", keyStr.c_str());
        result = PDO_ERR_VALUE;
        goto done;
    }
    else
    {
        std::string valueStr = map[keyStr];
        Log(PDO_LOG_DEBUG, "Block store found key: '%s' -> '%s'", keyStr.c_str(), valueStr.c_str());

        size_t storedValSize = valueStr.size() / 2;
        if (inValueSize != storedValSize)
        {
            Log(PDO_LOG_ERROR, "Requested block of size %zu but buffer size is %zu", inValueSize,
                storedValSize);
            result = PDO_ERR_VALUE;
            goto done;
        }

        // Deserialize the data from the cache into the buffer
        HexStringToBinary(outValue, inValueSize, valueStr);

        result = PDO_SUCCESS;
    }

done:
    pthread_spin_unlock(&lock);
    // UNLOCK
    // **********

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStorePut(
    const uint8_t* inId,
    const size_t inIdSize,
    const uint8_t* inValue,
    const size_t inValueSize
)
{
    std::string keyStr = BinaryToHexString(inId, inIdSize);
    std::string valueStr = BinaryToHexString(inValue, inValueSize);

    Log(PDO_LOG_DEBUG, "Block store Put: %zu bytes '%s' -> %zu bytes '%s'", inIdSize,
        keyStr.c_str(), inValueSize, valueStr.c_str());
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
pdo_err_t pdo::block_store::BlockStoreHead(
    const ByteArray& inId,
    bool* outIsPresent,
    size_t* outValueSize
)
{
    return BlockStoreHead(inId.data(), inId.size(), outIsPresent, outValueSize);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStoreGet(
    const ByteArray& inId,
    ByteArray& outValue
)
{
    pdo_err_t result = PDO_SUCCESS;

    // Get the size of the state block
    bool isPresent;
    size_t value_size;
    result = BlockStoreHead(inId.data(), inId.size(), &isPresent, &value_size);
    if (result != PDO_SUCCESS)
    {
        return result;
    }
    else if (!isPresent)
    {
        return PDO_ERR_VALUE;
    }

    // Resize the output array
    outValue.resize(value_size);

    // Fetch the state from the block storage
    result = BlockStoreGet(inId.data(), inId.size(), &outValue[0], value_size);
    if (result != PDO_SUCCESS)
    {
        return result;
    }

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStorePut(
    const ByteArray &inId,
    const ByteArray &inValue
)
{
    return BlockStorePut(inId.data(), inId.size(), inValue.data(), inValue.size());
}
