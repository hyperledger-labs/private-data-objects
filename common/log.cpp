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

#if _UNTRUSTED_

#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>

#include "log.h"
#include "c11_support.h"

#define FIXED_BUFFER_SIZE (1<<14)

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX Internal helper functions                              XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static void LogStdOut(
    pdo_log_level_t level,
    const char* message
    )
{
    printf("[LOG %u] %s", level, message);
} // LogStdOut

static pdo_log_t g_LogFunction = LogStdOut;

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
        pthread_mutex_lock(&mutex);
        g_LogFunction(level, message);
        pthread_mutex_unlock(&mutex);
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

#endif
