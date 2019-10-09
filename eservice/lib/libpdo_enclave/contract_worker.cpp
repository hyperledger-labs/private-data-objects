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

#include "enclave_t.h"

#include <string>
#include <vector>

#include "sgx_thread.h"
#include "contract_worker.h"

#include "interpreter/ContractInterpreter.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractWorker::ContractWorker(long thread_id)
{
    thread_id_ = thread_id;
    current_state_ = INTERPRETER_DONE;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractWorker::InitializeInterpreter(void)
{
    sgx_thread_mutex_lock(&mutex_);

    if (current_state_ == INTERPRETER_DONE)
    {
        if (interpreter_ == NULL) {
            interpreter_ = pdo::contracts::CreateInterpreter();
        } else {
            interpreter_->Initialize();
        }

        current_state_ = INTERPRETER_READY;
        sgx_thread_cond_signal(&ready_cond_);
    }

    sgx_thread_mutex_unlock(&mutex_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractWorker::WaitForCompletion(void)
{
    sgx_thread_mutex_lock(&mutex_);

    while (current_state_ != INTERPRETER_DONE)
    {
        sgx_thread_cond_wait(&done_cond_, &mutex_);
    }

    // doing this asynchronously might create some non-determinism around
    // memory allocation... need to watch
    if (interpreter_ != NULL)
        interpreter_->Finalize();

    sgx_thread_mutex_unlock(&mutex_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo::contracts::ContractInterpreter* ContractWorker::GetInitializedInterpreter(void)
{
    sgx_thread_mutex_lock(&mutex_);

    while (current_state_ != INTERPRETER_READY)
    {
        sgx_thread_cond_wait(&ready_cond_, &mutex_);
    }

    current_state_ = INTERPRETER_BUSY;

    sgx_thread_mutex_unlock(&mutex_);

    return interpreter_;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractWorker::MarkInterpreterDone(void)
{
    sgx_thread_mutex_lock(&mutex_);
    current_state_ = INTERPRETER_DONE;
    sgx_thread_cond_signal(&done_cond_);
    sgx_thread_mutex_unlock(&mutex_);
}
