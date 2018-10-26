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

#include <sgx_trts.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include "sgx_thread.h"

#include "error.h"
#include "packages/base64/base64.h"
#include "pdo_error.h"
#include "timer.h"
#include "types.h"
#include "zero.h"

#include "enclave_utils.h"

#include "base_enclave.h"
#include "contract_enclave.h"
#include "enclave_data.h"
#include "signup_enclave.h"

#include "contract_request.h"
#include "contract_response.h"
#include "contract_secrets.h"

ByteArray last_result;
ContractWorker *worker = NULL;
static bool worker_initialized = false;
static bool shutdown_worker = false;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_CreateContractWorker(size_t inThreadId){
    pdo_err_t result = PDO_SUCCESS;

    try {
        if (!worker_initialized)
        {
            worker = new ContractWorker((long) inThreadId);
            worker_initialized = true;
            SAFE_LOG(PDO_LOG_INFO, "ThreadID: %ld - ContractWorker created",
                (long) worker->threadId_);
        }

        while (!shutdown_worker)
        {
            worker->interpreterInit();
        }
    }
    catch (pdo::error::Error& e)
    {
        printf("Error in contract enclave (ecall_CreateContractWorker): %04X -- %s \n", e.error_code(), e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    }
    catch (...)
    {
        printf("Unknown error in contract enclave (ecall_CreateContractWorker)\n");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_ShutdownContractWorker(){
    pdo_err_t result = PDO_SUCCESS;

    if (worker_initialized)
    {
        SAFE_LOG(PDO_LOG_INFO, "ThreadID: %ld - Shutting down ContractWorker",
            (long) worker->threadId_);
        shutdown_worker = true;
    }

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractWorker::ContractWorker(long threadId)
{
    this->threadId_ = threadId;
    this->current_state_ = INTERPRETER_DONE;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractWorker::interpreterInit()
{
    sgx_thread_mutex_lock(&this->mutex_);

    if (current_state_ == INTERPRETER_DONE) {
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
void ContractWorker::interpreterIsReady()
{
    sgx_thread_mutex_lock(&this->mutex_);

    while (!this->current_state_ == INTERPRETER_READY){
        sgx_thread_cond_wait(&this->ready_cond_, &this->mutex_);
        this->current_state_ = INTERPRETER_BUSY;
    }

    sgx_thread_mutex_unlock(&this->mutex_);
}


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractWorker::interpreterDone()
{
    sgx_thread_mutex_lock(&this->mutex_);
    this->current_state_ = INTERPRETER_DONE;
    sgx_thread_mutex_unlock(&this->mutex_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_VerifySecrets(const uint8_t* inSealedSignupData,
    size_t inSealedSignupDataSize,
    const char* inContractId,
    const char* inContractCreatorId,
    const char* inSerializedSecretList,
    uint8_t* outEncryptedContractKey,
    size_t inEncryptedContractKeyLength,
    uint8_t* outEncryptedContractKeySignature,
    size_t inEncryptedContractKeySignatureLength)
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        pdo::error::ThrowIfNull(inSealedSignupData, "Sealed signup data pointer is NULL");
        pdo::error::ThrowIfNull(inContractId, "Contract ID pointer is NULL");
        pdo::error::ThrowIfNull(inContractCreatorId, "Contract creator ID pointer is NULL");
        pdo::error::ThrowIfNull(inSerializedSecretList, "Secret list pointer is NULL");
        pdo::error::ThrowIfNull(outEncryptedContractKey, "Contract key pointer is NULL");
        pdo::error::ThrowIfNull(outEncryptedContractKeySignature, "Contract key signature is NULL");

        pdo_err_t presult;

        // Unseal the enclave persistent data
        EnclaveData enclaveData(inSealedSignupData);

        // Create the contract state encryption key
        ByteArray message;
        const std::string contractId(inContractId);
        const std::string creatorId(inContractCreatorId);
        const std::string secretList(inSerializedSecretList);
        ByteArray contractStateEncryptionKey;

        presult = CreateEnclaveStateEncryptionKey(
            enclaveData, contractId, creatorId, secretList, contractStateEncryptionKey, message);
        if (presult != PDO_SUCCESS)
            return presult;

        // Encrypt the contract state encryption key and save it in the output parameter
        ByteArray encrypted_state_encryption_key =
            EncryptStateEncryptionKey(contractId, contractStateEncryptionKey);
        pdo::error::ThrowIf<pdo::error::ValueError>(
            inEncryptedContractKeyLength < encrypted_state_encryption_key.size(),
            "Contract key length is too short");

        Zero(outEncryptedContractKey, inEncryptedContractKeyLength);
        memcpy_s(outEncryptedContractKey, inEncryptedContractKeyLength,
            encrypted_state_encryption_key.data(),
            encrypted_state_encryption_key.size());

        // Sign the transaction for the validator and save it

        // we need to tack on the encrypted state encryption key for
        // signing to the message that already has all the other pieces
        // needed for verification
        std::copy(encrypted_state_encryption_key.begin(), encrypted_state_encryption_key.end(),
            std::back_inserter(message));

        const ByteArray signature = enclaveData.sign_message(message);
        pdo::error::ThrowIf<pdo::error::ValueError>(
            inEncryptedContractKeySignatureLength < signature.size(),
            "Contract key signature is too short");

        Zero(outEncryptedContractKeySignature, inEncryptedContractKeySignatureLength);
        memcpy_s(outEncryptedContractKeySignature, inEncryptedContractKeySignatureLength,
            signature.data(), signature.size());
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Error in contract enclave (ecall_VerifySecrets): %04X -- %s",
            e.error_code(), e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Unknown error in contract enclave (ecall_VerifySecrets)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_HandleContractRequest(const uint8_t* inSealedSignupData,
    size_t inSealedSignupDataSize,
    const uint8_t* inEncryptedSessionKey,
    size_t inEncryptedSessionKeySize,
    const uint8_t* inSerializedRequest,
    size_t inSerializedRequestSize,
    size_t* outSerializedResponseSize)
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        pdo::error::ThrowIfNull(inSealedSignupData, "Sealed signup data pointer is NULL");
        pdo::error::ThrowIfNull(inEncryptedSessionKey, "Session key pointer is NULL");
        pdo::error::ThrowIfNull(inSerializedRequest, "Serialized request pointer is NULL");
        pdo::error::ThrowIfNull(outSerializedResponseSize, "Response size pointer is NULL");
        pdo::error::ThrowIfNull(worker, "worker pointer is NULL");

        // Unseal the enclave persistent data
        EnclaveData enclaveData(inSealedSignupData);

        ByteArray encrypted_key(
            inEncryptedSessionKey, inEncryptedSessionKey + inEncryptedSessionKeySize);
        ByteArray session_key = enclaveData.decrypt_message(encrypted_key);

        ByteArray encrypted_request(
            inSerializedRequest, inSerializedRequest + inSerializedRequestSize);
        ContractRequest request(session_key, encrypted_request, worker);

        ContractResponse response(request.process_request());
        last_result = response.SerializeAndEncrypt(session_key, enclaveData);

        // save the response and return the size of the buffer required for it
        (*outSerializedResponseSize) = last_result.size();
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "Error in contract enclave (ecall_HandleContractRequest): %04X -- %s", e.error_code(),
            e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Unknown error in contract enclave (ecall_HandleContractRequest)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_GetSerializedResponse(const uint8_t* inSealedSignupData,
    size_t inSealedSignupDataSize,
    uint8_t* outSerializedResponse,
    size_t inSerializedResponseSize)
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        pdo::error::ThrowIfNull(inSealedSignupData, "Sealed signup data pointer is NULL");
        pdo::error::ThrowIfNull(outSerializedResponse, "Serialized response pointer is NULL");
        pdo::error::ThrowIf<pdo::error::ValueError>(
            inSerializedResponseSize < last_result.size(), "Not enough space for the response");

        // Unseal the enclave persistent data
        EnclaveData enclaveData(inSealedSignupData);

        memcpy_s(outSerializedResponse, inSerializedResponseSize, last_result.data(),
            last_result.size());
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "Error in contract enclave(ecall_GetSerializedResponse): %04X -- %s", e.error_code(),
            e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Unknown error in contract enclave (ecall_GetSerializedResponse)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}
