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

void pdo::Log(
        pdo_log_level_t logLevel,
        const char* message,
        ...)
{
    const size_t BUFFER_SIZE = FIXED_BUFFER_SIZE;
    char msg[BUFFER_SIZE] = { '\0' };
    va_list ap;
    va_start(ap, message);
    vsnprintf_s(msg, BUFFER_SIZE, message, ap);
    va_end(ap);
    puts(msg);
} // Log

void Log(int level, const char* fmt, ...) {
    const size_t BUFFER_SIZE = FIXED_BUFFER_SIZE;
    char msg[BUFFER_SIZE] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf_s(msg, BUFFER_SIZE, fmt, ap);
    va_end(ap);
    puts(msg);
}
