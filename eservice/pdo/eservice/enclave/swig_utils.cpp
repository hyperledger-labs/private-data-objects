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
#include <chrono>
#include <pthread.h>

#include <Python.h>

#include <iostream>

#include "c11_support.h"
#include "error.h"
#include "log.h"
#include "pdo_error.h"

#include "enclave/base.h"

#include "swig_utils.h"

#define FIXED_BUFFER_SIZE (1<<14)

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
void SetLogger(
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
static PyGILState_STATE gstate;
static void PyLog(
    pdo_log_level_t type,
    const char *msg
    )
{
    // note that the log function wraps this with a mutex so we don't
    // need to

    if (!glogger)
    {
        printf("PyLog called before logger set, msg %s \n", msg);
        return;
    }

    //Ensures GIL is available on current thread for python callbacks
    gstate = PyGILState_Ensure();

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
    PyGILState_Release(gstate);
    //Releases GIL for other threads

} // PyLog

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
uint64_t GetTimer()
{
    uint64_t value;

    std::chrono::time_point<std::chrono::high_resolution_clock> now = std::chrono::high_resolution_clock::now();
    value = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    return value;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static pthread_mutex_t g_request_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_request_identifier = 0;
uint64_t GetRequestIdentifier(void)
{
    uint64_t result;
    pthread_mutex_lock(&g_request_mutex);
    {
        result = g_request_identifier;
        g_request_identifier++;
    }
    pthread_mutex_unlock(&g_request_mutex);

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void InitializePDOEnclaveModule()
{
    pdo::logger::SetLogFunction(PyLog);
} // InitializePDOEnclaveModule

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void TerminateInternal()
{
    SetLogger(NULL);
} // TerminateInternal
