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
#include <sys/time.h>

#include "lmdb.h"

#include "c11_support.h"
#include "error.h"
#include "hex_string.h"
#include "pdo_error.h"
#include "types.h"
#include "log.h"
#include "zero.h"

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
#define BLOCK_DB_NAME "block_data"
#define META_DB_NAME "meta_data"

static MDB_env* lmdb_block_store_env;

class SafeTransaction
{
public:
    MDB_dbi dbi_ = 0;
    MDB_dbi meta_dbi_ = 0;
    MDB_txn* txn_ = NULL;

    SafeTransaction(unsigned int txn_flags = 0, unsigned int dbi_flags = 0) {
        int ret;
        ret = mdb_txn_begin(lmdb_block_store_env, NULL, txn_flags, &txn_);
        if (ret == MDB_SUCCESS)
        {
            ret = mdb_dbi_open(txn_, BLOCK_DB_NAME, dbi_flags, &dbi_);
            if (ret == MDB_SUCCESS)
            {
                ret = mdb_dbi_open(txn_, META_DB_NAME, dbi_flags, &meta_dbi_);
                if (ret == MDB_SUCCESS)
                    return;
            }
        }

        SAFE_LOG(PDO_LOG_ERROR, "Failed to open LMDB transaction : %d", ret);
        if (txn_ != NULL)
        {
            mdb_txn_abort(txn_);
            txn_ = NULL;
        }

        throw pdo::error::SystemError("failed to open LMDB transaction");
    }

    ~SafeTransaction(void) {
        if (txn_ != NULL)
        {
            SAFE_LOG(PDO_LOG_INFO, "abort transaction due to exception");
            mdb_txn_abort(txn_);
        }
    }

    void abort(void) {
        pdo::error::ThrowIfNull(txn_, "duplicate abort of LMDB transaction");
        mdb_txn_abort(txn_);
        txn_ = NULL;
    }

    void commit(void) {
        pdo::error::ThrowIfNull(txn_, "duplicate commit of LMDB transaction");
        mdb_txn_commit(txn_);
        txn_ = NULL;
    }
};

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static pdo_err_t get_data(
    MDB_dbi dbi,
    MDB_txn* txn,
    const uint8_t* inId,
    const size_t inIdSize,
    uint8_t* outValue,
    const size_t inValueSize)
{
    MDB_val lmdb_id;
    lmdb_id.mv_size = inIdSize;
    lmdb_id.mv_data = (void*)inId;

    MDB_val lmdb_data;
    int ret = mdb_get(txn, dbi, &lmdb_id, &lmdb_data);
    if (ret == MDB_NOTFOUND)
    {
        SAFE_LOG(PDO_LOG_DEBUG, "data not found");
        return PDO_ERR_NOTFOUND;
    }

    if (ret != MDB_SUCCESS)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error reading data; %d", ret);
        return PDO_ERR_SYSTEM;
    }

    if (inValueSize < lmdb_data.mv_size)
    {
        SAFE_LOG(PDO_LOG_ERROR, "insufficient space allocated for data block");
        return PDO_ERR_SYSTEM;
    }

    memcpy_s(outValue, inValueSize, lmdb_data.mv_data, lmdb_data.mv_size);
    return PDO_SUCCESS;
}

static pdo_err_t put_data(
    MDB_dbi dbi,
    MDB_txn* txn,
    const uint8_t* inId,
    const size_t inIdSize,
    const uint8_t* inValue,
    const size_t inValueSize)
{
    MDB_val lmdb_id;
    lmdb_id.mv_size = inIdSize;
    lmdb_id.mv_data = (void*)inId;

    MDB_val lmdb_data;
    lmdb_data.mv_size = inValueSize;
    lmdb_data.mv_data = (void*)inValue;

    int ret = mdb_put(txn, dbi, &lmdb_id, &lmdb_data, 0);
    if (ret != MDB_SUCCESS)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Failed to put into LMDB database : %d", ret);
        return PDO_ERR_SYSTEM;
    }

    return PDO_SUCCESS;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Block metadata contains the last write time and the last read time,
// the size of the block, and an unsigned integer tag that can be used
// for garbage collection.
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
typedef struct
{
    size_t block_size_;
    uint64_t create_time_;      // seconds since epoch when block added to the store
    uint64_t expiration_time_;  // seconds since epoch when block storage contract expires
    uint64_t tag_;
} BlockMetaData;

static pdo_err_t get_metadata(
    MDB_dbi dbi,
    MDB_txn* txn,
    const uint8_t* inId,
    const size_t inIdSize,
    BlockMetaData *metadata)
{
    Zero(metadata, sizeof(BlockMetaData));
    return get_data(dbi, txn, inId, inIdSize, (uint8_t*)metadata, sizeof(BlockMetaData));
}

static pdo_err_t put_metadata(
    MDB_dbi dbi,
    MDB_txn* txn,
    const uint8_t* inId,
    const size_t inIdSize,
    const BlockMetaData *metadata)
{
    return put_data(dbi, txn, inId, inIdSize, (uint8_t*)metadata, sizeof(BlockMetaData));
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void pdo::lmdb_block_store::BlockStoreOpen(const std::string& db_path)
{
    SafeThreadLock slock;

    int ret;

    ret = mdb_env_create(&lmdb_block_store_env);
    pdo::error::ThrowIf<pdo::error::SystemError>(ret != 0, "Failed to create LMDB environment");

    ret = mdb_env_set_mapsize(lmdb_block_store_env, DEFAULT_BLOCK_STORE_SIZE);
    pdo::error::ThrowIf<pdo::error::SystemError>(ret != 0, "Failed to set LMDB default size");

    ret = mdb_env_set_maxdbs(lmdb_block_store_env, 2);
    pdo::error::ThrowIf<pdo::error::SystemError>(ret != 0, "Failed to set LMDB database count");

    /*
     * MDB_NOSUBDIR avoids creating an additional directory for the database
     * MDB_WRITEMAP | MDB_NOMETASYNC should substantially improve LMDB's performance
     * This risks possibly losing at most the last transaction if the system crashes
     * before it is written to disk.
     */
    unsigned int flags = MDB_NOSUBDIR | MDB_WRITEMAP | MDB_NOMETASYNC | MDB_MAPASYNC;
    ret = mdb_env_open(lmdb_block_store_env, db_path.c_str(), flags, 0664);
    pdo::error::ThrowIf<pdo::error::SystemError>(ret != 0, "Failed to open LMDB database");

    // Ensure that the databases are created
    SafeTransaction stxn(0, MDB_CREATE);
    stxn.commit();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
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
#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        SAFE_LOG(PDO_LOG_DEBUG, "BlockStoreHead: '%s'", idStr.c_str());
    }
#endif

    *outIsPresent = false;
    *outValueSize = 0;

    SafeTransaction stxn(MDB_RDONLY);

    if (stxn.txn_ == NULL)
        return PDO_ERR_SYSTEM;

    BlockMetaData metadata;
    pdo_err_t result = get_metadata(stxn.meta_dbi_, stxn.txn_, inId, inIdSize, &metadata);
    if (result == PDO_ERR_NOTFOUND)
        return PDO_SUCCESS;

    if (result != PDO_SUCCESS)
        return result;

    *outIsPresent = true;
    *outValueSize = metadata.block_size_;

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        SAFE_LOG(PDO_LOG_DEBUG, "Block store found id: '%s' -> '%zu'", idStr.c_str(), *outValueSize);
    }
#endif

    stxn.commit();
    return PDO_SUCCESS;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::block_store::BlockStoreGet(
    const uint8_t* inId,
    const size_t inIdSize,
    uint8_t* outValue,
    const size_t inValueSize)
{
    pdo_err_t result;

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        SAFE_LOG(PDO_LOG_DEBUG, "BlockStoreGet: '%s'", idStr.c_str());
    }
#endif

    SafeTransaction stxn(MDB_RDONLY);

    if (stxn.txn_ == NULL)
        return PDO_ERR_SYSTEM;

    // Get the block metadata, we can check the size first and then will
    // use it later to update the access time
    BlockMetaData metadata;
    result = get_metadata(stxn.meta_dbi_, stxn.txn_, inId, inIdSize, &metadata);
    if (result != PDO_SUCCESS)
    {
        SAFE_LOG(PDO_LOG_ERROR, "failed to retreive block metadata; %d", result);
        return result;
    }

    if (inValueSize < metadata.block_size_)
    {
        SAFE_LOG(PDO_LOG_ERROR, "insufficient space allocated for block data");
        return PDO_ERR_VALUE;
    }

    result = get_data(stxn.dbi_, stxn.txn_, inId, inIdSize, outValue, inValueSize);
    if (result != PDO_SUCCESS)
    {
        SAFE_LOG(PDO_LOG_ERROR, "failed to retreive block data; %d", result);
        return result;
    }

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        std::string valueStr = BinaryToHexString((uint8_t*)lmdb_data.mv_data, lmdb_data.mv_size);
        SAFE_LOG(PDO_LOG_DEBUG, "Block store found id: '%s' -> '%s'", idStr.c_str(), valueStr.c_str());
    }
#endif

    stxn.commit();
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
    pdo_err_t result;

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        SAFE_LOG(PDO_LOG_DEBUG, "BlockStorePut: '%s'", idStr.c_str());
    }
#endif

    SafeTransaction stxn(0);

    if (stxn.txn_ == NULL)
        return PDO_ERR_SYSTEM;

    result = put_data(stxn.dbi_, stxn.txn_, inId, inIdSize, inValue, inValueSize);
    if (result != PDO_SUCCESS)
    {
        SAFE_LOG(PDO_LOG_ERROR, "failed to write block data; %d", result);
        return result;
    }

    // update the last access time
    struct timeval now;
    gettimeofday(&now, NULL);

    BlockMetaData metadata;

    metadata.block_size_ = inValueSize;
    metadata.create_time_ = now.tv_sec;
    metadata.expiration_time_ = now.tv_sec + MINIMUM_EXPIRATION_TIME;
    metadata.tag_ = 0;
    result = put_metadata(stxn.meta_dbi_, stxn.txn_, inId, inIdSize, &metadata);
    if (result != PDO_SUCCESS)
    {
        SAFE_LOG(PDO_LOG_ERROR, "failed to save block meta data; %d", result);
        return result;
    }

#if BLOCK_STORE_DEBUG
    {
        std::string idStr = BinaryToHexString(inId, inIdSize);
        std::string valueStr = BinaryToHexString((uint8_t*)inValue, inValueSize);
        SAFE_LOG(PDO_LOG_DEBUG, "Block store wrote id: '%s' -> '%s'", idStr.c_str(), valueStr.c_str());
    }
#endif

    stxn.commit();
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
