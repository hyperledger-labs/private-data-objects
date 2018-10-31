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

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractWorker::ContractWorker(long thread_id)
{
    this->thread_id_ = thread_id;
    this->current_state_ = INTERPRETER_DONE;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractWorker::InitializeInterpreter(void)
{
    sgx_thread_mutex_lock(&this->mutex_);

    if (current_state_ == INTERPRETER_DONE)
    {
        if (interpreter_ != NULL) {
            delete interpreter_;
        }

        interpreter_ = new GipsyInterpreter();
        current_state_ = INTERPRETER_READY;
        sgx_thread_cond_signal(&this->ready_cond_);
    }

    sgx_thread_mutex_unlock(&this->mutex_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractWorker::WaitForCompletion(void)
{
    sgx_thread_mutex_lock(&this->mutex_);

    while (current_state_ != INTERPRETER_DONE)
    {
        sgx_thread_cond_wait(&this->done_cond_, &this->mutex_);
    }

    sgx_thread_mutex_unlock(&this->mutex_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
GipsyInterpreter *ContractWorker::GetInitializedInterpreter(void)
{
    sgx_thread_mutex_lock(&this->mutex_);

    while (!this->current_state_ == INTERPRETER_READY)
    {
        sgx_thread_cond_wait(&this->ready_cond_, &this->mutex_);
        this->current_state_ = INTERPRETER_BUSY;
    }

    sgx_thread_mutex_unlock(&this->mutex_);

    return this->interpreter_;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractWorker::MarkInterpreterDone(void)
{
    sgx_thread_mutex_lock(&this->mutex_);
    this->current_state_ = INTERPRETER_DONE;
    sgx_thread_cond_signal(&this->done_cond_);
    sgx_thread_mutex_unlock(&this->mutex_);
}
