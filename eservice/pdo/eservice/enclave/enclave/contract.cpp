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
size_t pdo::enclave_api::contract::EncryptedContractKeySize(
  size_t contractIdSize,
  int enclaveIndex)
{
  size_t encryptedContractKeySize;

  // the computation is a simple non-secret-data dependent computation
  // 	sgx_calc_sealed_data_size(contractIdSize, pdo::crypto::constants::SYM_KEY_LEN)
  // but alas there doesn't seem to be a way to call/link trusted function
  // in untrusted space. Hence we have do on Ecall for that  :-(

  // xxxxx call the enclave


  /// get the enclave id for passing into the ecall
  sgx_enclave_id_t enclaveid = g_Enclave[enclaveIndex].GetEnclaveId();
  pdo::logger::LogV(PDO_LOG_DEBUG, "ecall_CalculateSealedContractKeySize[%ld] %u ", (long)enclaveid, enclaveIndex);

  pdo_err_t presult = PDO_SUCCESS;
  sgx_status_t sresult =
    g_Enclave[enclaveIndex].CallSgx(
      [
	enclaveid,
	&presult,
	contractIdSize,
	&encryptedContractKeySize
      ]
      ()
      {
	sgx_status_t sresult_inner = ecall_CalculateSealedContractKeySize(
	  enclaveid,
	  &presult,
	  contractIdSize,
	  &encryptedContractKeySize);
	return pdo::error::ConvertErrorStatus(sresult_inner, presult);
      }
      );
  pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (ecall_CalculateSealedContractKeySize)");
  g_Enclave[enclaveIndex].ThrowPDOError(presult);

  return encryptedContractKeySize;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::contract::VerifySecrets(
    const Base64EncodedString& inSealedEnclaveData,
    const std::string& inContractId,
    const std::string& inContractCreatorId, /* contract creator's public key */
    const std::string& inSerializedSecretList, /* json */
    Base64EncodedString& outEncryptedContractKey,
    Base64EncodedString& outContractKeySignature,
    int enclaveIndex
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        ByteArray sealed_enclave_data = Base64EncodedStringToByteArray(inSealedEnclaveData);
        ByteArray encrypted_contract_key(pdo::enclave_api::contract::EncryptedContractKeySize(inContractId.size(), enclaveIndex));
        ByteArray contract_key_signature(pdo::enclave_api::base::GetSignatureMaxSize());
        size_t contract_key_signature_length;

        // xxxxx call the enclave

        /// get the enclave id for passing into the ecall
        sgx_enclave_id_t enclaveid = g_Enclave[enclaveIndex].GetEnclaveId();
        pdo::logger::LogV(PDO_LOG_DEBUG, "VerifySecrets[%ld] %u ", (long)enclaveid, enclaveIndex);

        pdo_err_t presult = PDO_SUCCESS;
        sgx_status_t sresult =
            g_Enclave[enclaveIndex].CallSgx(
                [
                    enclaveid,
                    &presult,
                    sealed_enclave_data,
                    inContractId,
                    inContractCreatorId,
                    inSerializedSecretList,
                    &encrypted_contract_key,
                    &contract_key_signature,
		    &contract_key_signature_length
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
                        contract_key_signature.size(),
			&contract_key_signature_length);
                    return pdo::error::ConvertErrorStatus(sresult_inner, presult);
                }
                );
        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (VerifySecrets)");
        g_Enclave[enclaveIndex].ThrowPDOError(presult);

	contract_key_signature.resize(contract_key_signature_length);

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
    const ByteArray& inEncryptedSessionKey,
    const ByteArray& inSerializedRequest,
    uint32_t& outResponseIdentifier,
    size_t& outSerializedResponseSize,
    int enclaveIndex
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        size_t response_size;
        ByteArray sealed_enclave_data = Base64EncodedStringToByteArray(inSealedEnclaveData);

        /// get the enclave id for passing into the ecall
        sgx_enclave_id_t enclaveid = g_Enclave[enclaveIndex].GetEnclaveId();
        pdo::logger::LogV(PDO_LOG_DEBUG, "HandleContractRequest[%ld] %u ", (long)enclaveid, enclaveIndex);

        pdo_err_t presult = PDO_SUCCESS;
        sgx_status_t sresult =
            g_Enclave[enclaveIndex].CallSgx(
                [
                    enclaveid,
                    &presult,
                    sealed_enclave_data,
                    inEncryptedSessionKey,
                    inSerializedRequest,
                    &response_size
                ]
                ()
                {
                    sgx_status_t sresult_inner = ecall_HandleContractRequest(
                        enclaveid,
                        &presult,
                        sealed_enclave_data.data(),
                        sealed_enclave_data.size(),
                        inEncryptedSessionKey.data(),
                        inEncryptedSessionKey.size(),
                        inSerializedRequest.data(),
                        inSerializedRequest.size(),
                        &response_size);
                    return pdo::error::ConvertErrorStatus(sresult_inner, presult);
                }
                );
        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (InitializeContract)");
        g_Enclave[enclaveIndex].ThrowPDOError(presult);

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
pdo_err_t pdo::enclave_api::contract::InitializeContractState(
    const Base64EncodedString& inSealedEnclaveData,
    const ByteArray& inEncryptedSessionKey,
    const ByteArray& inSerializedRequest,
    uint32_t& outResponseIdentifier,
    size_t& outSerializedResponseSize,
    int enclaveIndex
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        size_t response_size;
        ByteArray sealed_enclave_data = Base64EncodedStringToByteArray(inSealedEnclaveData);

        /// get the enclave id for passing into the ecall
        sgx_enclave_id_t enclaveid = g_Enclave[enclaveIndex].GetEnclaveId();
        pdo::logger::LogV(PDO_LOG_DEBUG, "HandleContractRequest[%ld] %u ", (long)enclaveid, enclaveIndex);

        pdo_err_t presult = PDO_SUCCESS;
        sgx_status_t sresult =
            g_Enclave[enclaveIndex].CallSgx(
                [
                    enclaveid,
                    &presult,
                    sealed_enclave_data,
                    inEncryptedSessionKey,
                    inSerializedRequest,
                    &response_size
                ]
                ()
                {
                    sgx_status_t sresult_inner = ecall_InitializeContractState(
                        enclaveid,
                        &presult,
                        sealed_enclave_data.data(),
                        sealed_enclave_data.size(),
                        inEncryptedSessionKey.data(),
                        inEncryptedSessionKey.size(),
                        inSerializedRequest.data(),
                        inSerializedRequest.size(),
                        &response_size);
                    return pdo::error::ConvertErrorStatus(sresult_inner, presult);
                }
                );
        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (InitializeContract)");
        g_Enclave[enclaveIndex].ThrowPDOError(presult);

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
    ByteArray& outSerializedResponse,
    int enclaveIndex
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        ByteArray sealed_enclave_data = Base64EncodedStringToByteArray(inSealedEnclaveData);

        outSerializedResponse.resize(inSerializedResponseSize);

        // xxxxx call the enclave

        /// get the enclave id for passing into the ecall
        sgx_enclave_id_t enclaveid = g_Enclave[enclaveIndex].GetEnclaveId();
        pdo::logger::LogV(PDO_LOG_DEBUG, "GetSerializedResponse[%ld] %u ", (long)enclaveid, enclaveIndex);

        pdo_err_t presult = PDO_SUCCESS;
        sgx_status_t sresult =

            g_Enclave[enclaveIndex].CallSgx(
                [
                    enclaveid,
                    &presult,
                    sealed_enclave_data,
                    &outSerializedResponse
                ]
                ()
                {
                    sgx_status_t sresult_inner = ecall_GetSerializedResponse(
                        enclaveid,
                        &presult,
                        sealed_enclave_data.data(),
                        sealed_enclave_data.size(),
                        outSerializedResponse.data(),
                        outSerializedResponse.size());
                    return pdo::error::ConvertErrorStatus(sresult_inner, presult);
                }
                );
        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (GetSerializedResponse)");
        g_Enclave[enclaveIndex].ThrowPDOError(presult);
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
