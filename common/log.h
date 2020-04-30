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

#include "pdo_error.h"

#define SAFE_LOG(LEVEL, FMT, ...)
#define SAFE_LOG1(LEVEL, MSG)

#define SAFE_LOG_EXCEPTION(MSG) SAFE_LOG(PDO_LOG_ERROR, "EXCEPTION: %s; %s", MSG, e.what())

// SAFE_LOG should be used for any logging statements that might end
// up in the enclave. With debugging off all logging messages will be
// removed completely
#if PDO_DEBUG_BUILD
#undef SAFE_LOG
#define SAFE_LOG(LEVEL, FMT, ...) pdo::logger::LogV((pdo_log_level_t)LEVEL, FMT, ##__VA_ARGS__)
#undef SAFE_LOG1
#define SAFE_LOG1(LEVEL, MSG) pdo::logger::Log((pdo_log_level_t)LEVEL, MSG)
#endif  /* PDO_DEBUG_BUILD */

namespace pdo
{
    namespace logger
    {
        typedef void (*pdo_log_t)(pdo_log_level_t,const char* message);

        void SetLogFunction(pdo_log_t logFunction);

        void Log(pdo_log_level_t level, const char* msg);
        void LogV(pdo_log_level_t level, const char* fmt, ...);
    }
}

#if _UNTRUSTED_
#define MALLINFO_F mallinfo
#else  /* _UNTRUSTED_ */
#define MALLINFO_F dlmallinfo
// this will be implemented by the enclave
extern void trusted_wrapper_ocall_Log(pdo_log_level_t level, const char* msg);
#endif  /* _UNTRUSTED_ */

/******************************************************************************
 * Memory logging defines
 *****************************************************************************/
// This structure definition is taken from the SGX SDK open-source code
#define MALLINFO_FIELD_TYPE int
struct mallinfo {
  MALLINFO_FIELD_TYPE arena;    /* non-mmapped space allocated from system */
  MALLINFO_FIELD_TYPE ordblks;  /* number of free chunks */
  MALLINFO_FIELD_TYPE smblks;   /* always 0 */
  MALLINFO_FIELD_TYPE hblks;    /* always 0 */
  MALLINFO_FIELD_TYPE hblkhd;   /* space in mmapped regions */
  MALLINFO_FIELD_TYPE usmblks;  /* maximum total allocated space */
  MALLINFO_FIELD_TYPE fsmblks;  /* always 0 */
  MALLINFO_FIELD_TYPE uordblks; /* total allocated space */
  MALLINFO_FIELD_TYPE fordblks; /* total free space */
  MALLINFO_FIELD_TYPE keepcost; /* releasable (via malloc_trim) space */
};

extern "C"
{
    extern struct mallinfo MALLINFO_F(void);
}

// Usage:
//      - place the LOG_MEMORY in a source file (e.g., of the enclave);
//      - compile, run and check out the logs
//
// Result:
//      - the two (string) fields display the function name and the line number where the memory stats was performed
//      - for the other three fields, see comments in data structure.
//        NOTE:
//        Inside an enclave, it should hold that
//        `a = u + f` AND `a <= HeapMaxSize`
//        where HeapMaxSize is the value set in enclave configuration xml file

#if PDO_DEBUG_BUILD
#define LOG_MEMORY \
    do {\
        struct mallinfo sm = MALLINFO_F(); \
        SAFE_LOG(PDO_LOG_INFO, "MLOG:%s:%u: <a=%d | u=%d | f=%d>\n", \
                __func__, __LINE__, sm.arena, sm.uordblks, sm.fordblks); \
    } while(0)
#else // PDO_DEBUG_BUILD
#define LOG_MEMORY
#endif //PDO_DEBUG_BUILD
