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

#pragma once

#include <unistd.h>
#include <ctype.h>

#define MAXIMUM_SAFE_ALLOCATION 1<<22

namespace pdo
{
    namespace contracts
    {
        void *safe_malloc_for_scheme(size_t request);
        void *safe_realloc_for_scheme(void* ptr, size_t request);
        void safe_free_for_scheme(void* ptr);
        void reset_safe_memory_allocator(void);
    };
};
