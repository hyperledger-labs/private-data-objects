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

#include <malloc.h>
#include <stdint.h>

#include "Util.h"

#include <new>

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

/* ----------------------------------------------------------------- *
 * NAME: copy_internal_pointer
 * ----------------------------------------------------------------- */
bool copy_internal_pointer(
    StringArray& result,
    uint8_t* pointer,
    uint32_t size)
{
#ifdef SAFE_INTERNAL_COPY
    // the safe way
    bool success = result.assign(pointer, size);
    free(pointer);
    return success;
#else
    // the efficient way
    return result.take(pointer, size);
#endif
}
