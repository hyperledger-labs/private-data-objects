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
#include "WasmExtensions.h"

#ifdef USE_WASI_SDK
#include <new>

// -----------------------------------------------------------------
// these functions do not appear to be defined in the wasi-sdk
// lib c++. an error is generally raised about the failure to link
// an import function. for ones with obvious implements like standard
// new and delete, we provide viable implementation. for others that
// are not supported, a message will be generated and the application
// will abort.
// -----------------------------------------------------------------

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

void * operator new(size_t sz, std::align_val_t v)
{
    CONTRACT_SAFE_LOG(4, "attempt to invoke unsupported aligned allocation");
    std::abort();
}

void operator delete(void *ptr) _NOEXCEPT
{
    free(ptr);
}

void operator delete(void *ptr, std::align_val_t) _NOEXCEPT
{
    CONTRACT_SAFE_LOG(4, "attempt to invoke unsupported aligned deallocation");
    std::abort();
}

#include <stdio.h>
int vfprintf(FILE *__restrict, const char *__restrict, __isoc_va_list)
{
    CONTRACT_SAFE_LOG(4, "attempt to invoke unsupported vfprintf");
    std::abort();

    return -1;
}

extern "C" void __cxa_pure_virtual(void)
{
    CONTRACT_SAFE_LOG(4, "missing pure virtual function");
    std::abort();
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
