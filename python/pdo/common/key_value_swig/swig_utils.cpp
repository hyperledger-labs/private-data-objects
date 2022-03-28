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

#include "log.h"
#include "swig_utils.h"

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

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void InitializeKeyValueModule()
{
    pdo::logger::SetLogFunction(PyLog);
} // InitializePDOEnclaveModule

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void TerminateInternal()
{
    SetLogger(NULL);
} // TerminateInternal
