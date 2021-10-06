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

#include "bh_platform.h"
#include "wasm_export.h"
#include "lib_export.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern "C" bool key_value_set_wrapper(
    wasm_exec_env_t exec_env,
    const int32 kv_store_handle,
    const uint8_t* key_buffer,
    const int32 key_buffer_length,
    const uint8_t* val_buffer,
    const int32 val_buffer_length);

extern "C" bool key_value_get_wrapper(
    wasm_exec_env_t exec_env,
    const int32 kv_store_handle,
    const uint8_t* key_buffer,
    const int32 key_buffer_length,
    int32 val_buffer_pointer_offset,  /* uint8_t** */
    int32 val_length_pointer_offset); /* size_t* */

extern "C" bool privileged_key_value_get_wrapper(
    wasm_exec_env_t exec_env,
    const uint8_t* key_buffer,
    const int32 key_buffer_length,
    int32 val_buffer_pointer_offset,  /* uint8_t** */
    int32 val_length_pointer_offset); /* size_t* */

extern "C" int key_value_create_wrapper(
    wasm_exec_env_t exec_env,
    const uint8_t* key_buffer,
    const int32 key_buffer_length);

extern "C" int key_value_open_wrapper(
    wasm_exec_env_t exec_env,
    const uint8_t* id_hash_buffer,
    const int32 id_hash_buffer_length,
    const uint8_t* key_buffer,
    const int32 key_buffer_length);

extern "C" bool key_value_finalize_wrapper(
    wasm_exec_env_t exec_env,
    const int32 kv_start_handle,
    int32 id_hash_buffer_pointer_offset,  /* uint8_t** */
    int32 id_hash_length_pointer_offset); /* size_t* */
