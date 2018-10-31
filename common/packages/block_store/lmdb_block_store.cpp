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

#include "lmdb.h"

#include "c11_support.h"
#include "error.h"
#include "hex_string.h"
#include "pdo_error.h"
#include "types.h"
#include "log.h"

/* Common API for all block stores */
#include "block_store.h"
/* API for this specific LMDB-backed block store */
#include "lmdb_block_store.h"

/*
 * This must be a multiple of the page size (4096)
 *
 * Default to an insanely large max size (1 TB)
 */
#define DEFAULT_BLOCK_STORE_SIZE (1ULL << 40)

/* Lightning database environment used to store data */
static MDB_env* env;
/* Lock to protect access to the database */
static pthread_spinlock_t lock;

pdo_err_t pdo::lmdb_block_store::BlockStoreInit(std::string db_path)
{
    int ret;

    ret = pthread_spin_init(&lock, PTHREAD_PROCESS_SHARED);
    if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to init block store spinlock: %d", ret);
        return PDO_ERR_SYSTEM;
    }

    ret = mdb_env_create(&env);
    if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to create LMDB environment: %d", ret);
        return PDO_ERR_SYSTEM;
    }

    ret = mdb_env_set_mapsize(env, DEFAULT_BLOCK_STORE_SIZE);
    if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to set LMDB size to %zu : %d",
            DEFAULT_BLOCK_STORE_SIZE, ret);
        mdb_env_close(env);
        return PDO_ERR_SYSTEM;
    }

    /*
     * MDB_NOSUBDIR avoids creating an additional directory for the database
     * MDB_WRITEMAP | MDB_NOMETASYNC should substantially improve LMDB's performance
     * This risks possibly losing at most the last transaction if the system crashes
     * before it is written to disk.
     */
    ret = mdb_env_open(env, db_path.c_str(), MDB_NOSUBDIR | MDB_WRITEMAP | MDB_NOMETASYNC | MDB_MAPASYNC, 0664);
    if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to open LMDB database '%s': %d", db_path.c_str(), ret);
        mdb_env_close(env);
        return PDO_ERR_SYSTEM;
    }

    return PDO_SUCCESS;
}

void pdo::lmdb_block_store::BlockStoreClose()
{
    mdb_env_close(env);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStoreHead(
    const uint8_t* inId,
    const size_t inIdSize,
    bool* outIsPresent,
    size_t* outValueSize
)
{
    MDB_txn* txn;
    MDB_dbi dbi;
    MDB_val lmdb_id;
    MDB_val lmdb_data;
    int ret;
    pdo_err_t result = PDO_SUCCESS;

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        Log(PDO_LOG_DEBUG, "BlockStoreHead: '%s'", idStr.c_str());
    }
#endif

    // **********
    // LOCK
    pthread_spin_lock(&lock);


    ret = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to get LMDB transaction: %d", ret);
        result = PDO_ERR_SYSTEM;
        goto unlock;
    }

    ret = mdb_dbi_open(txn, NULL, 0, &dbi);
    if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to open LMDB transaction : %d", ret);
        result = PDO_ERR_SYSTEM;
        goto close;
    }

    lmdb_id.mv_size = inIdSize;
    lmdb_id.mv_data = (void*)inId;

    ret = mdb_get(txn, dbi, &lmdb_id, &lmdb_data);
    if (ret == MDB_NOTFOUND)
    {
        *outIsPresent = false;
        goto close;
    }
    else if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to get from LMDB database : %d", ret);
        result = PDO_ERR_SYSTEM;
        goto close;
    }

    *outIsPresent = true;
    *outValueSize = lmdb_data.mv_size;

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        std::string valueStr = BinaryToHexString((uint8_t*)lmdb_data.mv_data, lmdb_data.mv_size);
        Log(PDO_LOG_DEBUG, "Block store found id: '%s' -> '%s'", idStr.c_str(), valueStr.c_str());
    }
#endif


close:
    /* Free's the handle but doesn't do anything else for read only */
    mdb_txn_commit(txn);

unlock:

    pthread_spin_unlock(&lock);
    // UNLOCK
    // **********

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStoreGet(
    const uint8_t* inId,
    const size_t inIdSize,
    uint8_t* outValue,
    const size_t inValueSize
)
{
    MDB_txn* txn;
    MDB_dbi dbi;
    MDB_val lmdb_id;
    MDB_val lmdb_data;
    int ret;
    pdo_err_t result = PDO_SUCCESS;

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        Log(PDO_LOG_DEBUG, "BlockStoreGet: '%s'", idStr.c_str());
    }
#endif

    // **********
    // LOCK
    pthread_spin_lock(&lock);


    ret = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn);
    if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to get LMDB transaction: %d", ret);
        result = PDO_ERR_SYSTEM;
        goto unlock;
    }

    ret = mdb_dbi_open(txn, NULL, 0, &dbi);
    if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to open LMDB transaction : %d", ret);
        result = PDO_ERR_SYSTEM;
        goto close;
    }

    lmdb_id.mv_size = inIdSize;
    lmdb_id.mv_data = (void*)inId;

    ret = mdb_get(txn, dbi, &lmdb_id, &lmdb_data);
    if (ret == MDB_NOTFOUND)
    {
        Log(PDO_LOG_ERROR, "Failed to find id in block store");
        result = PDO_ERR_VALUE;
        goto close;
    }
    else if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to get from LMDB database : %d", ret);
        result = PDO_ERR_SYSTEM;
        goto close;
    }
    else if (inValueSize != lmdb_data.mv_size)
    {
        Log(PDO_LOG_ERROR, "Requested block of size %zu but buffer size is %zu", inValueSize,
            lmdb_data.mv_size);
        result = PDO_ERR_VALUE;
        goto close;
    }

    memcpy_s(outValue, inValueSize, lmdb_data.mv_data, lmdb_data.mv_size);

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        std::string valueStr = BinaryToHexString((uint8_t*)lmdb_data.mv_data, lmdb_data.mv_size);
        Log(PDO_LOG_DEBUG, "Block store found id: '%s' -> '%s'", idStr.c_str(), valueStr.c_str());
    }
#endif


close:
    /* Free's the handle but doesn't do anything else for read only */
    mdb_txn_commit(txn);

unlock:

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
    MDB_txn* txn;
    MDB_dbi dbi;
    MDB_val lmdb_id;
    MDB_val lmdb_data;
    int ret;
    pdo_err_t result = PDO_SUCCESS;

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        std::string valueStr = BinaryToHexString(inValue, inValueSize);

        Log(PDO_LOG_DEBUG, "Block store Put: %zu bytes '%s' -> %zu bytes '%s'", inIdSize,
            idStr.c_str(), inValueSize, valueStr.c_str());
    }
#endif

    // **********
    // LOCK
    pthread_spin_lock(&lock);


    ret = mdb_txn_begin(env, NULL, 0, &txn);
    if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to get LMDB transaction: %d", ret);
        result = PDO_ERR_SYSTEM;
        goto unlock;
    }

    ret = mdb_dbi_open(txn, NULL, 0, &dbi);
    if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to open LMDB transaction : %d", ret);
        result = PDO_ERR_SYSTEM;
        goto close;
    }

    lmdb_id.mv_size = inIdSize;
    lmdb_id.mv_data = (void*)inId;
    lmdb_data.mv_size = inValueSize;
    lmdb_data.mv_data = (void*)inValue;

    ret = mdb_put(txn, dbi, &lmdb_id, &lmdb_data, 0);
    if (ret != 0)
    {
        Log(PDO_LOG_ERROR, "Failed to put to LMDB database : %d", ret);
        result = PDO_ERR_SYSTEM;
        goto close;
    }

close:
    mdb_txn_commit(txn);

unlock:

    pthread_spin_unlock(&lock);
    // UNLOCK
    // **********

    return result;
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
    const ByteArray& inId,
    const ByteArray& inValue
)
{
    return BlockStorePut(inId.data(), inId.size(), inValue.data(), inValue.size());
}
