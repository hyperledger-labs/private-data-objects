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

int ocall_BlockStoreHead(
    const uint8_t* inKey,
    const size_t inKeySize,
    size_t* outValueSize);

int ocall_BlockStoreGet(
    const uint8_t* inKey,
    const size_t inKeySize,
    uint8_t *outValue,
    const size_t inValueSize);

int ocall_BlockStorePut(
    const uint8_t* inKey,
    const size_t inKeySize,
    const uint8_t* inValue,
    const size_t inValueSize);
