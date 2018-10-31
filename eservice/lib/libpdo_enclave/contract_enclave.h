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

/***************************************************************************************************
FILENAME:      contract_enclave.h
DESCRIPTION:   Function declarations for the contract enclave
*******************************************************************************************************/

#pragma once

#include "error.h"
#include "sgx_thread.h"

#include "enclave_utils.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_CreateContractWorker(size_t inThreadId);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_ShutdownContractWorker();

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_VerifySecrets(const uint8_t* inSealedSignupData,
    size_t inSealedSignupDataSize,
    const char* inContractId,
    const char* inContractCreatorId,
    const char* inSerializedSecretList,
    char* outEncryptedContractKey,
    size_t inEncryptedContractKeyLength,
    char* outEncryptedContractKeySignature,
    size_t inEncryptedContractKeySignatureLength);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_InitializeContract(const uint8_t* inSealedSignupData,
    size_t inSealedSignupDataSize,
    const char* inEncryptedSessionKey,
    const char* inSerializedRequest,
    size_t* outSerializedResponseSize);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_UpdateContract(const uint8_t* inSealedSignupData,
    size_t inSealedSignupDataSize,
    const char* inEncryptedSessionKey,
    const char* inSerializedRequest,
    size_t* outSerializedResponseSize);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern pdo_err_t ecall_GetSerializedResponse(const uint8_t* inSealedSignupData,
    size_t inSealedSignupDataSize,
    char* outSerializedResponse,
    size_t inSerializedResponseSize);
