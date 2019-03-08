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

#include "enclave_t.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
/*
    the trusted_wrapper_ocall_Log function is required in, and used by,
    in the trusted common library. The library generates the log message
    and triggers the wrapper and so the ocall in untrusted space.
*/
void trusted_wrapper_ocall_Log(pdo_log_level_t level, const char* message)
{
#if PDO_DEBUG_BUILD
    ocall_Log(level, message);
#endif  // PDO_DEBUG_BUILD
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
uint64_t GetTimer(void)
{
    uint64_t value = 0;
#if PDO_DEBUG_BUILD
    ocall_GetTimer(&value);
#endif  // PDO_DEBUG_BUILD

    return value;
} // GetTimer
