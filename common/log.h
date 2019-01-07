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

#ifndef DEBUG
#define SAFE_LOG(LEVEL, FMT, ...)
#define SAFE_LOGV(LEVEL, FMT, ...)
#endif  /* DEBUG */

#if _UNTRUSTED_
#include "pdo_error.h"

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

// SAFE_LOG should be used for any logging statements that might end
// up in the enclave. With debugging off all logging messages will be
// removed completely

#ifdef DEBUG
#define SAFE_LOG(LEVEL, FMT, ...) pdo::logger::LogV(LEVEL, FMT, ##__VA_ARGS__)
#define SAFE_LOG1(LEVEL, MSG) pdo::logger::Log(LEVEL, MSG)
#endif  /* DEBUG */

#else  /* _UNTRUSTED_ */

// this will be implemented by the enclave
extern void Log(int level, const char* fmt, ...);

#ifdef DEBUG
#define SAFE_LOG(LEVEL, FMT, ...) Log(LEVEL, FMT, ##__VA_ARGS__)
#define SAFE_LOG1(LEVEL, MSG) Log(LEVEL, MSG)
#endif  /* DEBUG */

#endif  /* _UNTRUSTED_ */
