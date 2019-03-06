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

#include "TestEnclave.h"
#include "TestEnclave_t.h"
#include "testCrypto.h"
#include "pdo_error.h"
void trusted_wrapper_ocall_Log(pdo_log_level_t level, const char* message)
{
    ocall_Log(level, message);
}

// Test ECALL
int test()
{
    return pdo::crypto::testCrypto();
}
