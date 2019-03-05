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

#include <stdarg.h>
#include <stdio.h>

#include "log.h"
#include "c11_support.h"

#define FIXED_BUFFER_SIZE (1<<14)

#if _UNTRUSTED_

#include <pthread.h>

#define MUTEX_LOCK pthread_mutex_lock
#define MUTEX_UNLOCK pthread_mutex_unlock

// Internal helper function (untrusted space only)
static void LogStdOut(
    pdo_log_level_t level,
    const char* message
    )
{
    printf("[LOG %u] %s", level, message);
} // LogStdOut

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pdo_log_t g_LogFunction = LogStdOut;

#else // _UNTRUSTED_

#include "sgx_thread.h"

#define MUTEX_LOCK sgx_thread_mutex_lock
#define MUTEX_UNLOCK sgx_thread_mutex_unlock

static sgx_thread_mutex_t mutex = SGX_THREAD_MUTEX_INITIALIZER;
static pdo_log_t g_LogFunction = trusted_wrapper_ocall_Log;

#endif // _UNTRUSTED_


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX External interface                                     XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void pdo::logger::SetLogFunction(
    pdo_log_t logFunction
    )
{
    if (logFunction)
    {
        g_LogFunction = logFunction;
    }
} // SetLogFunction

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void pdo::logger::Log(
    pdo_log_level_t level,
    const char* message
    )
{
    if (g_LogFunction)
    {
        MUTEX_LOCK(&mutex);
        g_LogFunction(level, message);
        MUTEX_UNLOCK(&mutex);
    }
} // Log

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void pdo::logger::LogV(
    pdo_log_level_t level,
    const char* message,
    ...)
{
    if (g_LogFunction)
    {
        char msg[FIXED_BUFFER_SIZE] = { '\0' };
        va_list ap;
        va_start(ap, message);
        vsnprintf_s(msg, FIXED_BUFFER_SIZE, message, ap);
        va_end(ap);

        pdo::logger::Log(level, msg);
    }
} // Log
