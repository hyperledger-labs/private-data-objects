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

#include "enclave_u.h"

#include "pdo_error.h"
#include "error.h"
#include "log.h"
#include "types.h"
#include "zero.h"

#include "crypto.h"
#include "enclave/enclave.h"
#include "enclave/base.h"
#include "enclave/contract.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t pdo::enclave_api::contract::ContractKeySize(void)
{
    // this is somewhat lucky because we currently fit precisely
    // in the AES block; will need to pad if
    return pdo::crypto::constants::IV_LEN + pdo::crypto::constants::SYM_KEY_LEN + pdo::crypto::constants::TAG_LEN;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::contract::VerifySecrets(
    const Base64EncodedString& inSealedEnclaveData,
    const std::string& inContractId,
    const std::string& inContractCreatorId, /* contract creator's public key */
    const std::string& inSerializedSecretList, /* json */
    Base64EncodedString& outEncryptedContractKey,
    Base64EncodedString& outContractKeySignature
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        ByteArray sealed_enclave_data = Base64EncodedStringToByteArray(inSealedEnclaveData);
        ByteArray encrypted_contract_key(pdo::enclave_api::contract::ContractKeySize());
        ByteArray contract_key_signature(pdo::enclave_api::base::GetSignatureSize());

        // xxxxx call the enclave
        sgx_enclave_id_t enclaveid = g_Enclave.GetEnclaveId();

        pdo_err_t presult = PDO_SUCCESS;
        sgx_status_t sresult =
            g_Enclave.CallSgx(
                [
                    enclaveid,
                    &presult,
                    sealed_enclave_data, // not sure why this needs to be passed by reference...
                    inContractId,
                    inContractCreatorId,
                    inSerializedSecretList,
                    &encrypted_contract_key,
                    &contract_key_signature
                ]
                ()
                {
                    sgx_status_t sresult_inner = ecall_VerifySecrets(
                        enclaveid,
                        &presult,
                        sealed_enclave_data.data(),
                        sealed_enclave_data.size(),
                        inContractId.c_str(),
                        inContractCreatorId.c_str(),
                        inSerializedSecretList.c_str(),
                        encrypted_contract_key.data(),
                        encrypted_contract_key.size(),
                        contract_key_signature.data(),
                        contract_key_signature.size());
                    return pdo::error::ConvertErrorStatus(sresult_inner, presult);
                }
                );
        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (VerifySecrets)");
        g_Enclave.ThrowPDOError(presult);

        outEncryptedContractKey = ByteArrayToBase64EncodedString(encrypted_contract_key);
        outContractKeySignature = ByteArrayToBase64EncodedString(contract_key_signature);
    }
    catch (pdo::error::Error& e)
    {
        pdo::enclave_api::base::SetLastError(e.what());
        result = e.error_code();
    }
    catch (std::exception& e)
    {
        pdo::enclave_api::base::SetLastError(e.what());
        result = PDO_ERR_UNKNOWN;
    }
    catch (...)
    {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::contract::HandleContractRequest(
    const Base64EncodedString& inSealedEnclaveData,
    const Base64EncodedString& inEncryptedSessionKey,
    const Base64EncodedString& inSerializedRequest,
    uint32_t& outResponseIdentifier,
    size_t& outSerializedResponseSize
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        size_t response_size;
        ByteArray sealed_enclave_data = Base64EncodedStringToByteArray(inSealedEnclaveData);
        ByteArray encrypted_session_key = Base64EncodedStringToByteArray(inEncryptedSessionKey);
        ByteArray serialized_request = Base64EncodedStringToByteArray(inSerializedRequest);

        // xxxxx call the enclave
        sgx_enclave_id_t enclaveid = g_Enclave.GetEnclaveId();

        pdo_err_t presult = PDO_SUCCESS;
        sgx_status_t sresult =
            g_Enclave.CallSgx(
                [
                    enclaveid,
                    &presult,
                    sealed_enclave_data,
                    encrypted_session_key,
                    serialized_request,
                    &response_size
                ]
                ()
                {
                    sgx_status_t sresult_inner = ecall_HandleContractRequest(
                        enclaveid,
                        &presult,
                        sealed_enclave_data.data(),
                        sealed_enclave_data.size(),
                        encrypted_session_key.data(),
                        encrypted_session_key.size(),
                        serialized_request.data(),
                        serialized_request.size(),
                        &response_size);
                    return pdo::error::ConvertErrorStatus(sresult_inner, presult);
                }
                );
        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (InitializeContract)");
        g_Enclave.ThrowPDOError(presult);

        outSerializedResponseSize = response_size;

    }
    catch (pdo::error::Error& e)
    {
        pdo::enclave_api::base::SetLastError(e.what());
        result = e.error_code();
    }
    catch (std::exception& e)
    {
        pdo::enclave_api::base::SetLastError(e.what());
        result = PDO_ERR_UNKNOWN;
    }
    catch (...)
    {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::contract::GetSerializedResponse(
    const Base64EncodedString& inSealedEnclaveData,
    const uint32_t inResponseIdentifier,
    const size_t inSerializedResponseSize,
    Base64EncodedString& outSerializedResponse
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        ByteArray serialized_response(inSerializedResponseSize);
        ByteArray sealed_enclave_data = Base64EncodedStringToByteArray(inSealedEnclaveData);

        // xxxxx call the enclave
        sgx_enclave_id_t enclaveid = g_Enclave.GetEnclaveId();

        pdo_err_t presult = PDO_SUCCESS;
        sgx_status_t sresult =
            g_Enclave.CallSgx(
                [
                    enclaveid,
                    &presult,
                    sealed_enclave_data,
                    &serialized_response
                ]
                ()
                {
                    sgx_status_t sresult_inner = ecall_GetSerializedResponse(
                        enclaveid,
                        &presult,
                        sealed_enclave_data.data(),
                        sealed_enclave_data.size(),
                        serialized_response.data(),
                        serialized_response.size());
                    return pdo::error::ConvertErrorStatus(sresult_inner, presult);
                }
                );
        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (GetSerializedResponse)");
        g_Enclave.ThrowPDOError(presult);

        outSerializedResponse = ByteArrayToBase64EncodedString(serialized_response);
    }
    catch (pdo::error::Error& e)
    {
        pdo::enclave_api::base::SetLastError(e.what());
        result = e.error_code();
    }
    catch (std::exception& e)
    {
        pdo::enclave_api::base::SetLastError(e.what());
        result = PDO_ERR_UNKNOWN;
    }
    catch (...)
    {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}
