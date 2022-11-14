/*
 * Copyright (C) 2022 Intel Corporation.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <string>
#include <vector>

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define KV_STORE_POOL_MAX_SIZE 8

std::vector<uint8_t> key_value_set(
    const int32_t kv_store_handle,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& value);

std::vector<uint8_t> key_value_get(
    const int32_t kv_store_handle,
    const std::vector<uint8_t>& key);

int32_t key_value_create(
    const std::vector<uint8_t>& aes_encryption_key);

int32_t key_value_open(
    const std::vector<uint8_t>& id_hash,
    const std::vector<uint8_t>& aes_encryption_key);

std::vector<uint8_t> key_value_finalize(
    const int32_t kv_start_handle);
