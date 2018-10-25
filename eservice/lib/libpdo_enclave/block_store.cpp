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

/*
 * Within the enclave, the block store API is a wrapper around making
 * ocall's to retrieve state from the client
 */

#include <string.h>

#include "error.h"
#include "hex_string.h"
#include "pdo_error.h"
#include "types.h"

#include "block_store.h"

#include "enclave_t.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStoreHead(
    const uint8_t* inId,
    const size_t inIdSize,
    bool* outIsPresent,
    size_t* outValueSize
)
{
    pdo_err_t ret;
    int sgx_ret = ocall_BlockStoreHead(&ret, inId, inIdSize, outIsPresent, outValueSize);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        sgx_ret != 0, "sgx failed during head request on the block store");
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        ret != 0, "head request failed on the block store");

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
    pdo_err_t ret;
    int sgx_ret = ocall_BlockStoreGet(&ret, inId, inIdSize, outValue, inValueSize);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        sgx_ret != 0, "sgx failed during get request on the block store");
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        ret != 0, "get request failed on the block store");

    return PDO_SUCCESS;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStorePut(
    const uint8_t* inId,
    const size_t inIdSize,
    const uint8_t* inValue,
    const size_t inValueSize
)
{
    pdo_err_t ret;
    int sgx_ret = ocall_BlockStorePut(&ret, inId, inIdSize, inValue, inValueSize);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        sgx_ret != 0, "sgx failed during put to the block store");
    pdo::error::ThrowIf<pdo::error::RuntimeError>(ret != 0, "failed to put to the block store");

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
    return (pdo_err_t)BlockStorePut(inId.data(), inId.size(), inValue.data(), inValue.size());
}
