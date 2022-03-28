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

#include <stdlib.h>
#include <string>
#include <vector>
#include <map>

#include "error.h"
#include "pdo_error.h"

#include "packages/block_store/block_store.h"
#include "packages/block_store/lmdb_block_store.h"

#include "block_store.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void block_store_open(const std::string& db_path)
{
    pdo::lmdb_block_store::BlockStoreOpen(db_path);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void block_store_close()
{
    pdo::lmdb_block_store::BlockStoreClose();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::vector<uint8_t> block_store_get(const std::vector<uint8_t>& block_id)
{
    std::vector<uint8_t> block_data;
    pdo_err_t status = pdo::block_store::BlockStoreGet(block_id, block_data);
    pdo::error::ThrowIf<pdo::error::IndexError>(status != PDO_SUCCESS, "failed to fetch block");

    return block_data;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void block_store_put(const std::vector<uint8_t>& block_id, const std::vector<uint8_t>& block_data)
{
    pdo_err_t status = pdo::block_store::BlockStorePut(block_id, block_data);
    pdo::error::ThrowIf<pdo::error::IndexError>(status != PDO_SUCCESS, "failed to save block");
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::map<std::string, metadata_value_type_t> block_store_head(const std::vector<uint8_t>& block_id)
{
    pdo::block_store::BlockMetaData metadata;
    bool is_present;

    pdo_err_t status = pdo::block_store::BlockStoreHead(block_id, &is_present, &metadata);
    pdo::error::ThrowIf<pdo::error::IndexError>(
        status != PDO_SUCCESS || ! is_present,
        "failed to fetch block metadata");

    std::map<std::string, metadata_value_type_t> result;

    result["block_size"] = metadata.block_size_;
    result["create_time"] = metadata.create_time_;
    result["expiration_time"] = metadata.expiration_time_;
    result["tag"] = metadata.tag_;

    return result;
}
