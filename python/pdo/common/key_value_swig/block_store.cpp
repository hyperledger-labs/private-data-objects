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
    pdo_err_t result = pdo::block_store::BlockStoreGet(block_id, block_data);
    if (result != PDO_SUCCESS)
        throw std::runtime_error("failed to fetch block");

    return block_data;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void block_store_put(const std::vector<uint8_t>& block_id, const std::vector<uint8_t>& block_data)
{
    pdo_err_t result = pdo::block_store::BlockStorePut(block_id, block_data);
    if (result != PDO_SUCCESS)
        throw std::runtime_error("failed to save block");
}
