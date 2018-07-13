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

#include <stdint.h>

#include <sgx_report.h>
#include <sgx_tcrypto.h>

#include "hex_string.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define SECRET_SIZE pdo::crypto::constants::SYM_KEY_LEN
#define ENCODED_SECRET_SIZE HEX_STRING_SIZE(SECRET_SIZE)
#define SECRET_SIGNATURE_SIZE pdo::crypto::constants::MAX_SIG_SIZE
#define ENCODED_SECRET_SIGNATURE_SIZE HEX_STRING_SIZE(SECRET_SIGNATURE_SIZE)

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_CalculateSealedEnclaveDataSize(size_t* pSealedEnclaveDataSize);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_CalculatePublicEnclaveDataSize(size_t* pPublicEnclaveDataSize);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_CalculateSealedSecretSize(
    const size_t plain_len,
    size_t* pSealedSecretSize);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_CalculatePlainSecretSize(
    const uint8_t* inSealedSecret,
    size_t inSealedSecretSize,
    uint32_t* pPlainSecretSize);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_CreateEnclaveData(const sgx_target_info_t* inTargetInfo,
    char* outPublicEnclaveData,
    size_t inAllocatedPublicEnclaveDataSize,
    size_t* outPublicEnclaveDataSize,
    uint8_t* outSealedEnclaveData,
    size_t inAllocatedSealedEnclaveDataSize,
    size_t* outSealedEnclaveDataSize,
    sgx_report_t* outEnclaveReport);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_UnsealEnclaveData(const uint8_t* inSealedEnclaveData,
    size_t inSealedEnclaveDataSize,
    char* outPublicEnclaveData,
    size_t inAllocatedPublicEnclaveDataSize,
    size_t* outPublicEnclaveDataSize);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_CreateSealedSecret(size_t secret_len,
    uint8_t* outSealedSecret,
    size_t inAllocatedSealedSecretSize);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_UnsealSecret(const uint8_t* inSealedSecret,
    size_t inSealedSecretSize,
    uint8_t* outPlainSecret,
    uint32_t inAllocatedPlainSecretSize);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_GenerateEnclaveSecret(
    const uint8_t* inSealedEnclaveData,
    size_t inSealedEnclaveDataSize,
    const uint8_t* inSealedSecret,
    size_t inSealedSecretSize,
    const char* inContractId,
    const char* inOpk,
    const char* inEnclaveInfo,
    uint8_t* outSignedSecret,
    size_t inAllocatedSignedSecretSize);
