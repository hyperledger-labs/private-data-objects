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

#include <stdlib.h>

typedef enum {
    PDO_SUCCESS=0,
    PDO_ERR_UNKNOWN=-1,
    PDO_ERR_MEMORY=-2,
    PDO_ERR_IO =-3,
    PDO_ERR_RUNTIME=-4,
    PDO_ERR_INDEX=-5,
    PDO_ERR_DIVIDE_BY_ZERO=-6,
    PDO_ERR_OVERFLOW =-7,
    PDO_ERR_VALUE =-8,
    PDO_ERR_SYSTEM =-9,
    PDO_ERR_SYSTEM_BUSY =-10,  /*
                                  Indicates that the system is busy and
                                  the operation may be retried again.  If
                                  retries fail this should be converted to
                                  a PDO_ERR_SYSTEM for reporting.
                                */
    PDO_ERR_CRYPTO = -11,
    PDO_ERR_NOTFOUND = -12
} pdo_err_t;

typedef enum {
    PDO_LOG_DEBUG = 0,
    PDO_LOG_INFO = 1,
    PDO_LOG_WARNING = 2,
    PDO_LOG_ERROR = 3,
    PDO_LOG_CRITICAL = 4,
} pdo_log_level_t;

typedef void (*pdo_log_t)(
    pdo_log_level_t,
    const char* message
    );
