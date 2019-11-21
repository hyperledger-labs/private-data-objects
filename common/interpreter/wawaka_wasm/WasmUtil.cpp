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

#include "error.h"
#include "log.h"
#include "pdo_error.h"
#include "types.h"

#include "WasmUtil.h"

namespace pe = pdo::error;

/* ----------------------------------------------------------------- *
 * NAME: get_buffer
 * ----------------------------------------------------------------- */
void* get_buffer(
    wasm_module_inst_t module_inst,
    const int32 buffer_offset,
    const int32 length)
{
    if (! wasm_runtime_validate_app_addr(module_inst, buffer_offset, length))
    {
        SAFE_LOG(PDO_LOG_INFO, "invalid address");
        return NULL;
    }

    return wasm_runtime_addr_app_to_native(module_inst, buffer_offset);
}

/* ----------------------------------------------------------------- *
 * NAME: save_buffer
 * ----------------------------------------------------------------- */
bool save_buffer(
    wasm_module_inst_t module_inst,
    const char* source_data,
    const uint32_t source_size,
    const int32 buffer_pointer_offset,
    const int32 length_pointer_offset)
{
    if (! wasm_runtime_validate_app_addr(module_inst, buffer_pointer_offset, sizeof(void*)))
    {
        SAFE_LOG(PDO_LOG_INFO, "invalid address passed as buffer pointer");
        return false;
    }

    if (! wasm_runtime_validate_app_addr(module_inst, length_pointer_offset, sizeof(uint32_t)))
    {
        SAFE_LOG(PDO_LOG_INFO, "invalid address passed as length pointer");
        return false;
    }

    int32* buffer_pointer = (int32*)wasm_runtime_addr_app_to_native(module_inst, buffer_pointer_offset);
    uint32_t* length_pointer = (uint32_t*)wasm_runtime_addr_app_to_native(module_inst, length_pointer_offset);

    int32 buffer = wasm_runtime_module_dup_data(module_inst, source_data, source_size);
    if (buffer == 0)
    {
        SAFE_LOG(PDO_LOG_INFO, "failed to allocate memory for byte array");
        return false;
    }

    (*buffer_pointer) = buffer;
    (*length_pointer) = source_size;

    return true;
}

/* ----------------------------------------------------------------- *
 * NAME: save_buffer
 * ----------------------------------------------------------------- */
bool save_buffer(
    wasm_module_inst_t module_inst,
    const ByteArray& source,
    const int32 buffer_pointer_offset,
    const int32 length_pointer_offset)
{
    return save_buffer(
        module_inst,
        (const char*)source.data(), source.size(),
        buffer_pointer_offset, length_pointer_offset);
}

/* ----------------------------------------------------------------- *
 * NAME: save_buffer
 * ----------------------------------------------------------------- */
bool save_buffer(
    wasm_module_inst_t module_inst,
    const std::string& source,
    const int32 buffer_pointer_offset,
    const int32 length_pointer_offset)
{
    return save_buffer(
        module_inst,
        source.c_str(), source.length(),
        buffer_pointer_offset, length_pointer_offset);
}
