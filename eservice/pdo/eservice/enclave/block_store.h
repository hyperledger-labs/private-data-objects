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

#include <string>
#include <map>

/**
 * Initialize the block store - must be called before performing gets/puts
 *
 *  Success (return PDO_SUCCESS) - Block store ready to use
 *  Failure (return nonzero) - Block store is unusable
 */
pdo_err_t block_store_init();

/**
 * Gets the size of a block in the block store
 *
 * @param key_b64       base64 encoded key string
 *
 * @return
 *  Success: length of value corresponding to key
 *  Failure: -1
 */
int block_store_head(
    const std::string& key_b64
    );

/**
 * Gets the value corresponding to a key from the block store
 *
 * @param key_b64       base64 encoded key string
 *
 * @return
 *  Success: base64 encoded value corresponding to key
 *  Failure: throws exception
 */
std::string block_store_get(
    const std::string& key_b64
    );

/**
 * Puts a key->value pair into the block store
 *
 * @param key_b64       base64 encoded key string
 * @param value_b64     base64 encoded value string
 *
 * @return
 *  Success: void/no return
 *  Failure: throws exception
 */
void block_store_put(
    const std::string& key_b64,
    const std::string& value_b64
    );
