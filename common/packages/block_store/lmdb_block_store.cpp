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

/* -----------------------------------------------------------------
 * CLASS: SafeThreadLock
 *
 * This class initializes the lock for serializing  and wraps transactions to
 * ensure that the resources are released when the object is deallocated.
 * ----------------------------------------------------------------- */

/* Lock to protect access to the database */
static pthread_mutex_t lmdb_block_store_lock = PTHREAD_MUTEX_INITIALIZER;

class SafeThreadLock
{
public:
    SafeThreadLock(void)
    {
        pthread_mutex_lock(&lmdb_block_store_lock);
    }

    ~SafeThreadLock(void)
    {
        pthread_mutex_unlock(&lmdb_block_store_lock);
    }
};

/* -----------------------------------------------------------------
 * CLASS: SafeTransaction
 *
 * This class initializes the lmdb database and wraps transactions to
 * ensure that the resources are released when the object is deallocated.
 * ----------------------------------------------------------------- */

/* Lightning database environment used to store data */
static MDB_env* lmdb_block_store_env;

class SafeTransaction
{
public:
    MDB_txn* txn = NULL;

    SafeTransaction(unsigned int flags) {
        int ret = mdb_txn_begin(lmdb_block_store_env, NULL, flags, &txn);
        if (ret != MDB_SUCCESS)
        {
            SAFE_LOG(PDO_LOG_ERROR, "Failed to initialize LMDB transaction; %d", ret);
            txn = NULL;
        }
    }

    ~SafeTransaction(void) {
        if (txn != NULL)
            mdb_txn_commit(txn);
    }
};

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::lmdb_block_store::BlockStoreInit(const std::string& db_path)
{
    int ret;

    ret = mdb_env_create(&lmdb_block_store_env);
    pdo::error::ThrowIf<pdo::error::SystemError>(ret != 0, "Failed to create LMDB environment");

    ret = mdb_env_set_mapsize(lmdb_block_store_env, DEFAULT_BLOCK_STORE_SIZE);
    pdo::error::ThrowIf<pdo::error::SystemError>(ret != 0, "Failed to set LMDB default size");

    /*
     * MDB_NOSUBDIR avoids creating an additional directory for the database
     * MDB_WRITEMAP | MDB_NOMETASYNC should substantially improve LMDB's performance
     * This risks possibly losing at most the last transaction if the system crashes
     * before it is written to disk.
     */
    ret = mdb_env_open(lmdb_block_store_env, db_path.c_str(), MDB_NOSUBDIR | MDB_WRITEMAP | MDB_NOMETASYNC | MDB_MAPASYNC, 0664);
    if (ret != 0)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Failed to open LMDB database; %d", ret);
        return PDO_ERR_SYSTEM;
    }

    return PDO_SUCCESS;
}

void pdo::lmdb_block_store::BlockStoreClose()
{
    if (lmdb_block_store_env != NULL)
        mdb_env_close(lmdb_block_store_env);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStoreHead(
    const uint8_t* inId,
    const size_t inIdSize,
    bool* outIsPresent,
    size_t* outValueSize
)
{
    MDB_dbi dbi;
    MDB_val lmdb_id;
    MDB_val lmdb_data;
    int ret;

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        SAFE_LOG(PDO_LOG_DEBUG, "BlockStoreHead: '%s'", idStr.c_str());
    }
#endif

    SafeThreadLock slock;      // lock by construction
    SafeTransaction stxn(MDB_RDONLY);

    if (stxn.txn == NULL)
        return PDO_ERR_SYSTEM;

    ret = mdb_dbi_open(stxn.txn, NULL, 0, &dbi);
    if (ret != 0)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Failed to open LMDB transaction : %d", ret);
        *outIsPresent = false;
        return PDO_ERR_SYSTEM;
    }

    lmdb_id.mv_size = inIdSize;
    lmdb_id.mv_data = (void*)inId;

    ret = mdb_get(stxn.txn, dbi, &lmdb_id, &lmdb_data);
    if (ret == MDB_NOTFOUND)
    {
        *outIsPresent = false;
        return PDO_SUCCESS;
    }
    else if (ret != 0)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Failed to get from LMDB database : %d", ret);
        *outIsPresent = false;
        return PDO_ERR_SYSTEM;
    }

    *outIsPresent = true;
    *outValueSize = lmdb_data.mv_size;

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        std::string valueStr = BinaryToHexString((uint8_t*)lmdb_data.mv_data, lmdb_data.mv_size);
        SAFE_LOG(PDO_LOG_DEBUG, "Block store found id: '%s' -> '%s'", idStr.c_str(), valueStr.c_str());
    }
#endif

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
    MDB_dbi dbi;
    MDB_val lmdb_id;
    MDB_val lmdb_data;
    int ret;

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        SAFE_LOG(PDO_LOG_DEBUG, "BlockStoreGet: '%s'", idStr.c_str());
    }
#endif

    SafeThreadLock slock;
    SafeTransaction stxn(MDB_RDONLY);

    if (stxn.txn == NULL)
        return PDO_ERR_SYSTEM;

    ret = mdb_dbi_open(stxn.txn, NULL, 0, &dbi);
    if (ret != 0)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Failed to open LMDB transaction : %d", ret);
        return PDO_ERR_SYSTEM;
    }

    lmdb_id.mv_size = inIdSize;
    lmdb_id.mv_data = (void*)inId;

    ret = mdb_get(stxn.txn, dbi, &lmdb_id, &lmdb_data);
    if (ret == MDB_NOTFOUND)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Failed to find id in block store");
        return PDO_ERR_VALUE;
    }
    else if (ret != 0)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Failed to get from LMDB database : %d", ret);
        return PDO_ERR_SYSTEM;
    }
    else if (inValueSize != lmdb_data.mv_size)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Requested block of size %zu but buffer size is %zu", inValueSize,
            lmdb_data.mv_size);
        return PDO_ERR_VALUE;
    }

    memcpy_s(outValue, inValueSize, lmdb_data.mv_data, lmdb_data.mv_size);

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        std::string valueStr = BinaryToHexString((uint8_t*)lmdb_data.mv_data, lmdb_data.mv_size);
        SAFE_LOG(PDO_LOG_DEBUG, "Block store found id: '%s' -> '%s'", idStr.c_str(), valueStr.c_str());
    }
#endif

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
    MDB_dbi dbi;
    MDB_val lmdb_id;
    MDB_val lmdb_data;
    int ret;

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        std::string valueStr = BinaryToHexString(inValue, inValueSize);

        SAFE_LOG(PDO_LOG_DEBUG, "Block store Put: %zu bytes '%s' -> %zu bytes '%s'", inIdSize,
            idStr.c_str(), inValueSize, valueStr.c_str());
    }
#endif

    SafeThreadLock slock;
    SafeTransaction stxn(0);

    if (stxn.txn == NULL)
        return PDO_ERR_SYSTEM;

    ret = mdb_dbi_open(stxn.txn, NULL, 0, &dbi);
    if (ret != 0)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Failed to open LMDB transaction : %d", ret);
        return PDO_ERR_SYSTEM;
    }

    lmdb_id.mv_size = inIdSize;
    lmdb_id.mv_data = (void*)inId;
    lmdb_data.mv_size = inValueSize;
    lmdb_data.mv_data = (void*)inValue;

    ret = mdb_put(stxn.txn, dbi, &lmdb_id, &lmdb_data, 0);
    if (ret != 0)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Failed to put to LMDB database : %d", ret);
        return PDO_ERR_SYSTEM;
    }

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
    const ByteArray& inId,
    const ByteArray& inValue
)
{
    return BlockStorePut(inId.data(), inId.size(), inValue.data(), inValue.size());
}
