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

#include "bh_platform.h"
#include "wasm_export.h"
#include "lib_export.h"

#include "basic_kv.h"
#include "error.h"
#include "interpreter_kv.h"
#include "log.h"
#include "pdo_error.h"
#include "types.h"

//#include <stddef.h>   /* size_t */
#include <string.h>
#include <ctype.h>
#include <math.h>

#include "WawakaInterpreter.h"
#include "WasmStateExtensions.h"
#include "WasmUtil.h"

namespace pe = pdo::error;
namespace pstate = pdo::state;

/* ----------------------------------------------------------------- *
 * NAME: _key_value_set_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool key_value_set_wrapper(
    wasm_exec_env_t exec_env,
    const int32 kv_store_handle,
    const uint8_t* key_buffer,
    const int32 key_buffer_length, // size_t
    const uint8_t* val_buffer,
    const int32 val_buffer_length) // size_t
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        if (kv_store_handle < 0 || kv_store_handle >= KV_STORE_POOL_MAX_SIZE)
        {
            SAFE_LOG(PDO_LOG_ERROR, "invalid state handle");
            return false;
        }

        pstate::Basic_KV_Plus** kv_store_pool = (pstate::Basic_KV_Plus**)wasm_runtime_get_custom_data(module_inst);
        pstate::Basic_KV_Plus* state = kv_store_pool[kv_store_handle];
        if (state == NULL)
        {
            SAFE_LOG(PDO_LOG_ERROR, "state was not initialized (set)");
            return false;
        }

        if (key_buffer == NULL)
            return false;

        if (val_buffer == NULL)
            return false;

        ByteArray ba_key(key_buffer, key_buffer + key_buffer_length);
        ByteArray ba_val(val_buffer, val_buffer + val_buffer_length);

        state->UnprivilegedPut(ba_key, ba_val);
        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: _key_value_get_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool key_value_get_wrapper(
    wasm_exec_env_t exec_env,
    const int32 kv_store_handle,
    const uint8_t* key_buffer,
    const int32 key_buffer_length, // size_t
    int32 val_buffer_pointer_offset, // uint8_t**
    int32 val_length_pointer_offset) // size_t*
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        if (kv_store_handle < 0 || kv_store_handle >= KV_STORE_POOL_MAX_SIZE)
        {
            SAFE_LOG(PDO_LOG_ERROR, "invalid state handle");
            return false;
        }

        pstate::Basic_KV_Plus** kv_store_pool = (pstate::Basic_KV_Plus**)wasm_runtime_get_custom_data(module_inst);
        pstate::Basic_KV_Plus* state = kv_store_pool[kv_store_handle];
        if (state == NULL)
        {
            SAFE_LOG(PDO_LOG_ERROR, "state was not initialized (get)");
            return false;
        }

        if (key_buffer == NULL)
            return false;

        ByteArray ba_key(key_buffer, key_buffer + key_buffer_length);
        ByteArray ba_val = state->UnprivilegedGet(ba_key);

        if (ba_val.size() == 0)
            return false;

        if (! save_buffer(module_inst,
                          (const char*)ba_val.data(), ba_val.size(),
                          val_buffer_pointer_offset, val_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: _key_value_create_wrapper
 * ----------------------------------------------------------------- */
extern "C" int32 key_value_create_wrapper(
    wasm_exec_env_t exec_env,
    const uint8_t* key_buffer,
    const int32 key_buffer_length)
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        if (key_buffer == NULL || key_buffer_length != 16)
        {
            SAFE_LOG(PDO_LOG_ERROR, "invalid encryption key; %d", key_buffer_length);
            return false;
        }

        ByteArray ba_encryption_key(key_buffer, key_buffer + key_buffer_length);

        // find an empty slot we can use for the kv store
        pstate::Basic_KV_Plus** kv_store_pool = (pstate::Basic_KV_Plus**)wasm_runtime_get_custom_data(module_inst);

        size_t kv_store_handle;
        for (kv_store_handle = 1; kv_store_handle < KV_STORE_POOL_MAX_SIZE; kv_store_handle++)
            if (kv_store_pool[kv_store_handle] == NULL) break;

        if (kv_store_handle == KV_STORE_POOL_MAX_SIZE)
        {
            SAFE_LOG(PDO_LOG_WARNING, "no kv store handles available");
            return -1;
        }

        pstate::Interpreter_KV* state = new pstate::Interpreter_KV(ba_encryption_key);
        if (state == NULL)
        {
            SAFE_LOG(PDO_LOG_ERROR, "state was not initialized (get)");
            return -1;
        }

        kv_store_pool[kv_store_handle] = (pstate::Basic_KV_Plus*)state;
        return kv_store_handle;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return -1;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return -1;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: _key_value_open_wrapper
 * ----------------------------------------------------------------- */
extern "C" int32 key_value_open_wrapper(
    wasm_exec_env_t exec_env,
    const uint8_t* id_hash_buffer,
    const int32 id_hash_buffer_length,
    const uint8_t* key_buffer,
    const int32 key_buffer_length)
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        if (id_hash_buffer == NULL || id_hash_buffer_length <= 0)
            return false;

        ByteArray ba_id_hash(id_hash_buffer, id_hash_buffer + id_hash_buffer_length);

        if (key_buffer == NULL || key_buffer_length != 16)
        {
            SAFE_LOG(PDO_LOG_ERROR, "invalid encryption key; %d", key_buffer_length);
            return false;
        }

        ByteArray ba_encryption_key(key_buffer, key_buffer + key_buffer_length);

        // find an empty slot we can use for the kv store
        pstate::Basic_KV_Plus** kv_store_pool = (pstate::Basic_KV_Plus**)wasm_runtime_get_custom_data(module_inst);

        size_t kv_store_handle;
        for (kv_store_handle = 1; kv_store_handle < KV_STORE_POOL_MAX_SIZE; kv_store_handle++)
            if (kv_store_pool[kv_store_handle] == NULL) break;

        if (kv_store_handle == KV_STORE_POOL_MAX_SIZE)
        {
            SAFE_LOG(PDO_LOG_WARNING, "no kv store handles available");
            return -1;
        }

        pstate::Interpreter_KV* state = new pstate::Interpreter_KV(ba_id_hash, ba_encryption_key);
        if (state == NULL)
        {
            SAFE_LOG(PDO_LOG_ERROR, "state was not initialized (get)");
            return -1;
        }

        kv_store_pool[kv_store_handle] = (pstate::Basic_KV_Plus*)state;
        return kv_store_handle;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return -1;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return -1;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: _key_value_finalize_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool key_value_finalize_wrapper(
    wasm_exec_env_t exec_env,
    const int32 kv_store_handle,
    int32 id_hash_buffer_pointer_offset,
    int32 id_hash_length_pointer_offset)
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        if (kv_store_handle <= 0 || kv_store_handle >= KV_STORE_POOL_MAX_SIZE)
        {
            SAFE_LOG(PDO_LOG_WARNING, "invalid state handle");
            return false;
        }

        pstate::Basic_KV_Plus** kv_store_pool = (pstate::Basic_KV_Plus**)wasm_runtime_get_custom_data(module_inst);
        pstate::Basic_KV_Plus* state = kv_store_pool[kv_store_handle];
        if (state == NULL)
        {
            SAFE_LOG(PDO_LOG_ERROR, "state was not initialized (finalize)");
            return false;
        }

        // Call finalize and cross your fingers
        ByteArray ba_val;

        state->Finalize(ba_val);
        if (ba_val.size() == 0)
        {
            SAFE_LOG(PDO_LOG_ERROR, "failed to finalize key/value store");
            return false;
        }

        // Clean up the memory used
        delete state;
        kv_store_pool[kv_store_handle] = NULL;

        // Save the block identifier in the output parameters
        if (! save_buffer(module_inst,
                          (const char*)ba_val.data(), ba_val.size(),
                          id_hash_buffer_pointer_offset, id_hash_length_pointer_offset))
            return false;

        return true;

    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}
