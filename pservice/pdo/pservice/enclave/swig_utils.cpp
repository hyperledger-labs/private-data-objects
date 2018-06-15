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

#include <stdlib.h>
#include <stdio.h>
#include <string>

#include <Python.h>

#include <iostream>

#include "c11_support.h"
#include "pdo_error.h"

#include "enclave/base.h"

#include "swig_utils.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ThrowPDOError(
    pdo_err_t ret
    )
{
    if (ret == PDO_SUCCESS)
        return;

    std::string message = pdo::enclave_api::base::GetLastError();

    switch(ret)
    {
    case PDO_ERR_UNKNOWN:
        throw pdo::error::UnknownError(message);

    case PDO_ERR_MEMORY:
        throw pdo::error::MemoryError(message);

    case PDO_ERR_IO:
        throw pdo::error::IOError(message);

    case PDO_ERR_RUNTIME:
        throw pdo::error::RuntimeError(message);

    case PDO_ERR_INDEX:
        throw pdo::error::IndexError(message);

    case PDO_ERR_DIVIDE_BY_ZERO:
        throw pdo::error::DivisionByZero(message);

    case PDO_ERR_OVERFLOW:
        throw pdo::error::OverflowError(message);

    case PDO_ERR_VALUE:
        throw pdo::error::ValueError(message);

    case PDO_ERR_SYSTEM:
        throw pdo::error::SystemError(message);

    case PDO_ERR_SYSTEM_BUSY:
        throw pdo::error::SystemBusyError(message);

    default:
        throw std::runtime_error(message);
    }

} // ThrowPDOError

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static PyObject* glogger = NULL;
void _SetLogger(
    PyObject* inLogger
    )
{
    if (glogger) {
        Py_DECREF(glogger);
    }
    glogger = inLogger;
    if (glogger) {
        Py_INCREF(glogger);
    }
} // _SetLogger

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void PyLog(
    pdo_log_level_t type,
    const char *msg
    )
{
    if(!glogger) {
        printf("PyLog called before logger set, msg %s \n", msg);
        return;
    }

    // build msg-string
    PyObject *string = NULL;
    string = Py_BuildValue("s", msg);

    // call function depending on log level
    switch (type) {
        case PDO_LOG_INFO:
            PyObject_CallMethod(glogger, "info", "O", string);
            break;

        case PDO_LOG_WARNING:
            PyObject_CallMethod(glogger, "warn", "O", string);
            break;

        case PDO_LOG_ERROR:
            PyObject_CallMethod(glogger, "error", "O", string);
            break;

        case PDO_LOG_DEBUG:
            PyObject_CallMethod(glogger, "debug", "O", string);
            break;

        case PDO_LOG_CRITICAL:
            PyObject_CallMethod(glogger, "critical", "O", string);
            break;
    }
    Py_DECREF(string);
} // PyLog

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void PyLogV(
    pdo_log_level_t type,
    const char* message,
    ...
    )
{
    const int BUFFER_SIZE = 2048;
    char msg[BUFFER_SIZE] = { '\0' };
    va_list ap;
    va_start(ap, message);
    vsnprintf_s(msg, BUFFER_SIZE, BUFFER_SIZE-1, message, ap);
    va_end(ap);
    PyLog(type, msg);
} // PyLogV

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void InitializePDOEnclaveModule()
{
    // Intentionally left blank
} // InitializePDOEnclaveModule

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void TerminateInternal()
{
    _SetLogger(NULL);
} // TerminateInternal
