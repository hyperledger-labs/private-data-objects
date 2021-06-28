/* Copyright 2019 Intel Corporation
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
#include <stdint.h>

#include "Types.h"
#include "Util.h"

#ifdef USE_WASI_SDK
#include <new>

// this function does not appear to be defined in the wasi-sdk
// lib c++. we need
std::new_handler std::get_new_handler() _NOEXCEPT
{
    return NULL;
}

void * operator new(size_t sz) throw(std::bad_alloc)
{
    return malloc(sz);
}

void * operator new[](size_t sz) throw(std::bad_alloc)
{
    return malloc(sz);
}

void operator delete(void *ptr) _NOEXCEPT
{
    free(ptr);
}

#endif

/* ----------------------------------------------------------------- *
 * NAME: copy_internal_pointer
 * ----------------------------------------------------------------- */
bool copy_internal_pointer(
    ww::types::ByteArray& result,
    const uint8_t* pointer,
    const uint32_t size)
{
    result.assign(pointer,pointer+size);
    return true;
}
