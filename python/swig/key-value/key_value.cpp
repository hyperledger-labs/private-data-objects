/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
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

#include <string>

#include "key_value.h"

#include "basic_kv.h"
#include "crypto.h"
#include "error.h"
#include "interpreter_kv.h"
#include "log.h"
#include "pdo_error.h"
#include "types.h"

#include <stddef.h>   /* size_t */
#include <string.h>
#include <ctype.h>
#include <math.h>

namespace pe = pdo::error;
namespace pstate = pdo::state;

// this allocates a static array
#define KV_STORE_POOL_MAX_SIZE 8
static pstate::Basic_KV_Plus* kv_store_pool[KV_STORE_POOL_MAX_SIZE] = {};

/* ----------------------------------------------------------------- *
 * NAME: fetch_state_from_handle
 * ----------------------------------------------------------------- */
static pstate::Basic_KV_Plus* fetch_state_from_handle(
    const int32_t kv_store_handle)
{
    if (kv_store_handle < 0 || kv_store_handle >= KV_STORE_POOL_MAX_SIZE)
    {
        return NULL;
    }

    pstate::Basic_KV_Plus* state = kv_store_pool[kv_store_handle];
    if (state == NULL)
    {
        return NULL;
    }

    return state;
}

/* ----------------------------------------------------------------- *
 * NAME: _key_value_set
 * ----------------------------------------------------------------- */
std::vector<uint8_t> key_value_set(
    const int32_t kv_store_handle,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& value)

{
    pstate::Basic_KV_Plus* state = fetch_state_from_handle(kv_store_handle);
    if (state == NULL)
        throw std::runtime_error("invalid handle");

    state->UnprivilegedPut(key, value);
    return value;
}

/* ----------------------------------------------------------------- *
 * NAME: _key_value_get
 * ----------------------------------------------------------------- */
std::vector<uint8_t> key_value_get(
    const int32_t kv_store_handle,
    const std::vector<uint8_t>& key)
{
    pstate::Basic_KV_Plus* state = fetch_state_from_handle(kv_store_handle);
    if (state == NULL)
        throw std::runtime_error("invalid handle");

    return state->UnprivilegedGet(key);
}

/* ----------------------------------------------------------------- *
 * NAME: _key_value_create
 * ----------------------------------------------------------------- */
int32_t key_value_create(
    const std::vector<uint8_t>& aes_encryption_key)
{
    if (aes_encryption_key.size() != pdo::crypto::constants::SYM_KEY_LEN)
        throw std::runtime_error("invalid encryption key");

    // find an empty slot we can use for the kv store
    size_t kv_store_handle;
    for (kv_store_handle = 0; kv_store_handle < KV_STORE_POOL_MAX_SIZE; kv_store_handle++)
        if (kv_store_pool[kv_store_handle] == NULL) break;

    if (kv_store_handle == KV_STORE_POOL_MAX_SIZE)
        throw std::runtime_error("unable to allocate handle");

    pstate::Interpreter_KV* state = new pstate::Interpreter_KV(aes_encryption_key);
    if (state == NULL)
        throw std::runtime_error("unable to allocate state");

    kv_store_pool[kv_store_handle] = (pstate::Basic_KV_Plus*)state;
    return kv_store_handle;
}

/* ----------------------------------------------------------------- *
 * NAME: _key_value_open
 * ----------------------------------------------------------------- */
int32_t key_value_open(
    const std::vector<uint8_t>& id_hash,
    const std::vector<uint8_t>& aes_encryption_key)

{
    if (id_hash.size() == 0)
        throw std::runtime_error("invalid root hash");

    if (aes_encryption_key.size() != pdo::crypto::constants::SYM_KEY_LEN)
        throw std::runtime_error("invalid encryption key");

    // find an empty slot we can use for the kv store
    size_t kv_store_handle;
    for (kv_store_handle = 0; kv_store_handle < KV_STORE_POOL_MAX_SIZE; kv_store_handle++)
        if (kv_store_pool[kv_store_handle] == NULL) break;

    if (kv_store_handle == KV_STORE_POOL_MAX_SIZE)
        throw std::runtime_error("unable to allocate handle");

    pstate::Interpreter_KV* state = new pstate::Interpreter_KV(id_hash, aes_encryption_key);
    if (state == NULL)
        throw std::runtime_error("unable to allocate state");

    kv_store_pool[kv_store_handle] = (pstate::Basic_KV_Plus*)state;
    return kv_store_handle;
}

/* ----------------------------------------------------------------- *
 * NAME: _key_value_finalize
 * ----------------------------------------------------------------- */
std::vector<uint8_t> key_value_finalize(
    const int32_t kv_store_handle)
{
    pstate::Basic_KV_Plus* state = fetch_state_from_handle(kv_store_handle);
    if (state == NULL)
        throw std::runtime_error("invalid handle");

    // Call finalize and cross your fingers
    std::vector<uint8_t> hash_id;

    state->Finalize(hash_id);
    if (hash_id.size() == 0)
        throw std::runtime_error("failed to finalize kv store");

    // Clean up the memory used
    kv_store_pool[kv_store_handle] = NULL;
    delete state;

    return hash_id;
}
