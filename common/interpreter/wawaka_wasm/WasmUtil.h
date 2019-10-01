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

#include "types.h"

#include "bh_platform.h"
#include "wasm_export.h"
#include "lib_export.h"

extern void* get_buffer(
    wasm_module_inst_t module_inst,
    const int32 buffer_offset,
    const int32 length);

extern bool save_buffer(
    wasm_module_inst_t module_inst,
    const char* source_data,
    const uint32_t source_size,
    const int32 buffer_pointer_offset,
    const int32 length_pointer_offset);

extern bool save_buffer(
    wasm_module_inst_t module_inst,
    const ByteArray& source,
    const int32 buffer_pointer_offset,
    const int32 length_pointer_offset);

extern bool save_buffer(
    wasm_module_inst_t module_inst,
    const std::string& source,
    const int32 buffer_pointer_offset,
    const int32 length_pointer_offset);
