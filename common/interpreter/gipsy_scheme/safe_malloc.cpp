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

#include <unistd.h>
#include <ctype.h>

#include <exception>
#include <string>
#include <map>

#include "safe_malloc.h"
#include "error.h"
#include "pdo_error.h"
#include "log.h"

std::map<uint64_t, size_t> safe_malloc_map;

static size_t total_allocation;
static size_t high_water_mark;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void *pdo::contracts::safe_malloc_for_scheme(size_t request)
{
    if (MAXIMUM_SAFE_ALLOCATION < total_allocation + request)
    {
        SAFE_LOG(PDO_LOG_WARNING, "requested memory allocation exceeded; %zu + %zu", total_allocation, request);
        throw pdo::error::ValueError("excessive memory use");
    }

    void *ptr = malloc(request);
    if (ptr == NULL)
    {
        SAFE_LOG1(PDO_LOG_WARNING, "gipsy memory allocation failed");
        return ptr;
    }

    safe_malloc_map[(uint64_t)ptr] = request;
    total_allocation += request;

    if (high_water_mark < total_allocation)
        high_water_mark = total_allocation;

    return ptr;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void *pdo::contracts::safe_realloc_for_scheme(void* oldptr, size_t request)
{
    if (oldptr == NULL)
        return pdo::contracts::safe_malloc_for_scheme(request);

    // find the old pointer in the memory map and remove it
    std::map<uint64_t, size_t>::iterator it = safe_malloc_map.find((uint64_t)oldptr);
    if (it == safe_malloc_map.end())
    {
        SAFE_LOG1(PDO_LOG_ERROR, "attempt to reallocate memory not allocated");
        return NULL;
    }

    total_allocation -= it->second;
    safe_malloc_map.erase(it);

    // reallocate and update memory based on the new pointer
    void *newptr = realloc(oldptr, request);
    if (newptr == NULL)
    {
        SAFE_LOG1(PDO_LOG_WARNING, "gipsy memory allocation failed");
        return newptr;
    }

    safe_malloc_map[(uint64_t)newptr] = request;
    total_allocation += request;

    if (high_water_mark < total_allocation)
        high_water_mark = total_allocation;

    return newptr;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void pdo::contracts::safe_free_for_scheme(void* ptr)
{
    std::map<uint64_t, size_t>::iterator it = safe_malloc_map.find((uint64_t)ptr);
    if (it == safe_malloc_map.end())
    {
        SAFE_LOG1(PDO_LOG_ERROR, "attempt to free memory not allocated");
        return;
    }

    total_allocation -= it->second;
    safe_malloc_map.erase(it);
    free(ptr);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void pdo::contracts::reset_safe_memory_allocator(void)
{
    size_t total = 0;

    std::map<uint64_t, size_t>::iterator it  = safe_malloc_map.begin();
    while (it != safe_malloc_map.end())
    {
        free((void*)it->first);
        total += it->second;
        it++;
    }

    SAFE_LOG(PDO_LOG_DEBUG, "deallocated %zu bytes during reset; high water was %zu", total, high_water_mark);

    safe_malloc_map.clear();

    high_water_mark = 0;
    total_allocation = 0;
}
