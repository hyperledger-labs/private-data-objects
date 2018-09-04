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

#include "pdo_error.h"
#include "types.h"

namespace pdo
{
    namespace enclave_api
    {
        namespace block_store
        {
            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            pdo_err_t BlockStoreInit();

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            int BlockStoreGet(
                const uint8_t* key,
                const size_t keySize,
                uint8_t **value,
                size_t* valueSize
                );

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            int BlockStorePut(
                const uint8_t* key,
                const size_t keySize,
                const uint8_t* value,
                const size_t valueSize
                );

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            int BlockStoreHead(
                const ByteArray& inKey
                );

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            pdo_err_t BlockStoreGet(
                const ByteArray& inKey,
                ByteArray& outValue
                );

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            pdo_err_t BlockStorePut(
                const ByteArray& inKey,
                const ByteArray& inValue
                );

        } /* contract */
    }     /* enclave_api */
}         /* pdo */
