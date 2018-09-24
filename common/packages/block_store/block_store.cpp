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
#include "types.h"
#include "hex_string.h"

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
	if (ret != 0) {
		Log(PDO_LOG_DEBUG, "Failed to init block store spinlock: %d", ret);
		return PDO_ERR_SYSTEM;
	}

	return PDO_SUCCESS;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int pdo::block_store::BlockStoreHead(
    const uint8_t *inKey,
    const size_t inKeySize,
    size_t *outValueSize
)
{
	int result = PDO_SUCCESS;
	std::string keyStr = BinaryToHexString(inKey, inKeySize);
	Log(PDO_LOG_DEBUG, "BlockStoreHead: '%s'", keyStr.c_str());

	// **********
	// LOCK
	pthread_spin_lock(&lock);

	if (map.find(keyStr) == map.end()) {
		Log(PDO_LOG_DEBUG, "Failed to find key in block store map: '%s'",
		    keyStr.c_str());
		result = PDO_ERR_VALUE;
		goto done;
	} else {
		std::string valueStr = map[keyStr];
		Log(PDO_LOG_DEBUG, "Block store found key: '%s' -> '%s'",
		    keyStr.c_str(), valueStr.c_str());

		*outValueSize = valueStr.size() / 2;
		result = PDO_SUCCESS;
	}

done:
	pthread_spin_unlock(&lock);
	// UNLOCK
	// **********

	return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int pdo::block_store::BlockStoreGet(
    const uint8_t *inKey,
    const size_t inKeySize,
    uint8_t *outValue,
    const size_t inValueSize
)
{
	int result = PDO_SUCCESS;
	std::string keyStr = BinaryToHexString(inKey, inKeySize);
	Log(PDO_LOG_DEBUG, "Block store get: '%s'", keyStr.c_str());

	// **********
	// LOCK
	pthread_spin_lock(&lock);

	if (map.find(keyStr) == map.end()) {
		Log(PDO_LOG_DEBUG, "Failed to find key in block store map: '%s'",
		    keyStr.c_str());
		result = PDO_ERR_VALUE;
		goto done;
	} else {
		std::string valueStr = map[keyStr];
		Log(PDO_LOG_DEBUG, "Block store found key: '%s' -> '%s'",
		    keyStr.c_str(), valueStr.c_str());

		size_t storedValSize = valueStr.size() / 2;
		if (inValueSize != storedValSize) {
			Log(PDO_LOG_ERROR, "Requested block of size %zu but buffer size is %zu",
			    inValueSize, storedValSize);
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
int pdo::block_store::BlockStorePut(
    const uint8_t *inKey,
    const size_t inKeySize,
    const uint8_t *value,
    const size_t inValueSize
)
{
	std::string keyStr = BinaryToHexString(inKey, inKeySize);
	std::string valueStr = BinaryToHexString(value, inValueSize);

	Log(PDO_LOG_DEBUG, "Block store Put: %zu bytes '%s' -> %zu bytes '%s'",
	    inKeySize, keyStr.c_str(), inValueSize, valueStr.c_str());
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
int pdo::block_store::BlockStoreHead(
    const ByteArray &inKey
)
{
	size_t value_size;

	// Fetch the state from the block storage
	pdo_err_t result = (pdo_err_t)BlockStoreHead(inKey.data(), inKey.size(), &value_size);
	if (result != PDO_SUCCESS) {
		// No data found - return -1 for size
		return -1;
	}

	// Found data - return its size
	return (int)value_size;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStoreGet(
    const ByteArray &inKey,
    ByteArray &outValue
)
{
	pdo_err_t result = PDO_SUCCESS;

	// Get the size of the state block
	size_t value_size;
	result = (pdo_err_t)BlockStoreHead(inKey.data(), inKey.size(), &value_size);
	if (result != PDO_SUCCESS) {
		return result;
	}

	// Resize the output array
	outValue.resize(value_size);

	// Fetch the state from the block storage
	result = (pdo_err_t)BlockStoreGet(inKey.data(), inKey.size(),
	                                  &outValue[0], value_size);
	if (result != PDO_SUCCESS) {
		return result;
	}

	return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStorePut(
    const ByteArray &inKey,
    const ByteArray &inValue
)
{
	return (pdo_err_t)BlockStorePut(inKey.data(), inKey.size(),
	                                inValue.data(), inValue.size());
}
