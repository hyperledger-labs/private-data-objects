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

/**
 * Initialize the block store - must be called before performing gets/puts
 *
 * @param db_path       path to the persistent block store database
 */
void block_store_open(const std::string& db_path);

/**
 * Close the block store - must be called when exiting
 */
void block_store_close();

/**
 * Read/write a block from the current blockstore
 */

// this type is necessary because swig is very unhappy about
// processing uint64_t. this is a known problem with SWIG
typedef unsigned long int metadata_value_type_t;

std::vector<uint8_t> block_store_get(const std::vector<uint8_t>& block_id);
void block_store_put(const std::vector<uint8_t>& block_id, const std::vector<uint8_t>& block_data);
std::map<std::string,metadata_value_type_t> block_store_head(const std::vector<uint8_t>& block_id);
