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

#include "wrapper_ocall_BlockStore.h"
#include "enclave_t.h"

int wrapper_ocall_BlockStoreHead(
    const uint8_t* inKey,
    size_t inKeySize,
    size_t* outValueSize) {
    int ret;
    ocall_BlockStoreHead(&ret, inKey, inKeySize, outValueSize);
    return ret;
}

int wrapper_ocall_BlockStoreGet(
    const uint8_t* inKey,
    size_t inKeySize,
    uint8_t* outValue,
    size_t inValueSize) {
    int ret;
    ocall_BlockStoreGet(&ret, inKey, inKeySize, outValue, inValueSize);
    return ret;
}

int wrapper_ocall_BlockStorePut(
    const uint8_t* inKey,
    size_t inKeySize,
    const uint8_t* inValue,
    size_t inValueSize) {
    int ret;
    ocall_BlockStorePut(&ret, inKey, inKeySize, inValue, inValueSize);
    return ret;
}
