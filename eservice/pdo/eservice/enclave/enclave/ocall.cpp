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

#include <stdint.h>
#include <stdio.h>
#include <iostream>
#include <chrono>

#include "log.h"
#include "packages/block_store/block_store.h"
#include "timer.h"

std::string g_enclaveError;

extern "C" {

    void ocall_Log(
        pdo_log_level_t level,
        const char *str
        )
    {
        pdo::logger::Log((pdo_log_level_t)level, str);
    } // ocall_Log

    void ocall_GetTimer(uint64_t* value)
    {
        (*value) = GetTimer();
    }

    void ocall_SetErrorMessage(
        const char* message
        )
    {
        if (message) {
            g_enclaveError.assign(message);
        } else {
            g_enclaveError.clear();
        }
    } // ocall_SetErrorMessage

    pdo_err_t ocall_BlockStoreHead(
        const uint8_t* inKey,
        const size_t inKeySize,
        bool* outIsPresent,
        size_t* outValueSize
        )
    {
        return pdo::block_store::BlockStoreHead(inKey, inKeySize, outIsPresent, outValueSize);
    } // ocall_BlockStoreHead

    pdo_err_t ocall_BlockStoreGet(
        const uint8_t* inKey,
        const size_t inKeySize,
        uint8_t *outValue,
        const size_t inValueSize
        )
    {
        return pdo::block_store::BlockStoreGet(inKey, inKeySize, outValue, inValueSize);
    } // ocall_BlockStoreGet

    pdo_err_t ocall_BlockStorePut(
        const uint8_t* inKey,
        const size_t inKeySize,
        const uint8_t* inValue,
        const size_t inValueSize
        )
    {
        return pdo::block_store::BlockStorePut(inKey, inKeySize, inValue, inValueSize);
    } // ocall_BlockStorePut
} // extern "C"
