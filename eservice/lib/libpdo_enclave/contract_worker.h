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

#include "error.h"
#include "sgx_thread.h"

#include "enclave_utils.h"

#include "interpreter/ContractInterpreter.h"

class ContractWorker
{

protected:
    enum interpreter_state{
        INTERPRETER_READY = 0,
        INTERPRETER_BUSY = -1,
        INTERPRETER_DONE = 1
    };

    interpreter_state current_state_;

    sgx_thread_mutex_t mutex_ = SGX_THREAD_MUTEX_INITIALIZER;
    sgx_thread_cond_t ready_cond_ = SGX_THREAD_COND_INITIALIZER;
    sgx_thread_cond_t done_cond_ = SGX_THREAD_COND_INITIALIZER;

    pdo::contracts::ContractInterpreter *interpreter_ = NULL;

public:

    long thread_id_;
    ContractWorker(long thread_id);
    ~ContractWorker(void)
    {
        if (interpreter_ != NULL)
            delete interpreter_;
    }

    void InitializeInterpreter(void);
    void WaitForCompletion(void);
    pdo::contracts::ContractInterpreter *GetInitializedInterpreter(void);
    void MarkInterpreterDone(void);
};

class InitializedInterpreter
{

public:
    ContractWorker *worker_ = NULL;
    pdo::contracts::ContractInterpreter *interpreter_ = NULL;

    InitializedInterpreter(ContractWorker* worker)
    {
        worker_ = worker;
        interpreter_ = worker_->GetInitializedInterpreter();
    }

    ~InitializedInterpreter(void)
    {
        worker_->MarkInterpreterDone();
    }
};
