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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <cctype>
#include <iterator>

#include <sgx_key.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <sgx_utils.h>  // sgx_get_key, sgx_create_report

#include "crypto.h"
#include "error.h"
#include "pdo_error.h"
#include "zero.h"

#include "base_enclave.h"
#include "enclave_data.h"
#include "enclave_utils.h"
#include "secret_enclave.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX Declaration of static helper functions                         XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

static void CreateSignupReportData(const char* pOriginatorPublicKeyHash,
    const EnclaveData& enclaveData,
    sgx_report_data_t* pReportData);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_CalculateSealedEnclaveDataSize(size_t* pSealedEnclaveDataSize)
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        pdo::error::ThrowIfNull(pSealedEnclaveDataSize, "Sealed enclave data size pointer is NULL");

        *pSealedEnclaveDataSize = EnclaveData::cMaxSealedDataSize;
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "Error in pdo enclave(ecall_CalculateSealedEnclaveDataSize): %04X -- %s",
            e.error_code(), e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    }
    catch (...)
    {
        SAFE_LOG(
            PDO_LOG_ERROR, "Unknown error in pdo enclave(ecall_CalculateSealedEnclaveDataSize)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}  // ecall_CalculateSealedEnclaveDataSize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_CalculatePublicEnclaveDataSize(size_t* pPublicEnclaveDataSize)
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        pdo::error::ThrowIfNull(pPublicEnclaveDataSize, "Publicp enclave data size pointer is NULL");

        *pPublicEnclaveDataSize = EnclaveData::cMaxPublicDataSize;
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "Error in pdo enclave(ecall_CalculatePublicEnclaveDataSize): %04X -- %s",
            e.error_code(), e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    }
    catch (...)
    {
        SAFE_LOG(
            PDO_LOG_ERROR, "Unknown error in pdo enclave(ecall_CalculatePublicEnclaveDataSize)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}  // ecall_CalculatePublicEnclaveDataSize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_CalculateSealedSecretSize(size_t plain_len, size_t* pSealedSecretSize)
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        pdo::error::ThrowIfNull(pSealedSecretSize, "Sealed secret size pointer is NULL");

        *pSealedSecretSize = sgx_calc_sealed_data_size(0, plain_len);;
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "Error in pdo enclave(ecall_CalculateSealedSecretSize): %04X -- %s",
            e.error_code(), e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    }
    catch (...)
    {
        SAFE_LOG(
            PDO_LOG_ERROR, "Unknown error in pdo enclave(ecall_CalculateSealedSecretSize)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}  // ecall_CalculateSealedSecretSize


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_CalculatePlainSecretSize(const uint8_t* inSealedSecret, size_t inSealedSecretSize, uint32_t* pPlainSecretSize)
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        pdo::error::ThrowIfNull(inSealedSecret, "Sealed secret pointer is NULL");
        pdo::error::ThrowIfNull(pPlainSecretSize, "Sealed secret size pointer is NULL");

        pdo::error::ThrowIf<pdo::error::ValueError>(!sgx_is_within_enclave(inSealedSecret,sizeof(sgx_sealed_data_t)),
            "sgx_sealed_data_t members NOT in enclave");

        *pPlainSecretSize = sgx_get_encrypt_txt_len(reinterpret_cast<const sgx_sealed_data_t*>(inSealedSecret));

    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "Error in pdo enclave(ecall_CalculateSealedSecretSize): %04X -- %s",
            e.error_code(), e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    }
    catch (...)
    {
        SAFE_LOG(
            PDO_LOG_ERROR, "Unknown error in pdo enclave(ecall_CalculateSealedSecretSize)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}  // ecall_CalculatePlainSecretSize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_CreateEnclaveData(const sgx_target_info_t* inTargetInfo,
    // const char* inOriginatorPublicKeyHash,
    char* outPublicEnclaveData,
    size_t inAllocatedPublicEnclaveDataSize,
    size_t* outPublicEnclaveDataSize,
    uint8_t* outSealedEnclaveData,
    size_t inAllocatedSealedEnclaveDataSize,
    size_t* outSealedEnclaveDataSize,
    sgx_report_t* outEnclaveReport)
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        pdo::error::ThrowIfNull(inTargetInfo, "Target info pointer is NULL");

        pdo::error::ThrowIfNull(outPublicEnclaveData, "Public enclave data pointer is NULL");
        pdo::error::ThrowIfNull(outPublicEnclaveDataSize, "Public data size pointer is NULL");

        pdo::error::ThrowIfNull(outSealedEnclaveData, "Sealed enclave data pointer is NULL");
        pdo::error::ThrowIfNull(outSealedEnclaveDataSize, "Sealed data size pointer is NULL");

        pdo::error::ThrowIfNull(outEnclaveReport, "SGX report pointer is NULL");

        (*outPublicEnclaveDataSize) = 0;
        Zero(outPublicEnclaveData, inAllocatedPublicEnclaveDataSize);

        (*outSealedEnclaveDataSize) = 0;
        Zero(outSealedEnclaveData, inAllocatedSealedEnclaveDataSize);

        // Create the enclave data
        EnclaveData enclaveData;

        pdo::error::ThrowIf<pdo::error::ValueError>(
            inAllocatedPublicEnclaveDataSize < enclaveData.get_public_data_size(),
            "Public enclave data buffer size is too small");

        pdo::error::ThrowIf<pdo::error::ValueError>(
            inAllocatedSealedEnclaveDataSize < enclaveData.get_sealed_data_size(),
            "Sealed enclave data buffer size is too small");

        // pass back the actual size of the enclave data
        (*outPublicEnclaveDataSize) = enclaveData.get_public_data_size();
        (*outSealedEnclaveDataSize) = enclaveData.get_sealed_data_size();;

        // Seal up the enclave data into the caller's buffer.
        // NOTE - the attributes mask 0xfffffffffffffff3 seems rather
        // arbitrary, but according to SGX SDK documentation, this is
        // what sgx_seal_data uses, so it is good enough for us.
        sgx_attributes_t attribute_mask = {0xfffffffffffffff3, 0};
        sgx_status_t ret = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, attribute_mask,
            0,        // misc_mask
            0,        // additional mac text length
            nullptr,  // additional mac text
            enclaveData.get_private_data_size(),
            reinterpret_cast<const uint8_t*>(enclaveData.get_private_data().c_str()),
            static_cast<uint32_t>(*outSealedEnclaveDataSize),
            reinterpret_cast<sgx_sealed_data_t*>(outSealedEnclaveData));
        pdo::error::ThrowSgxError(ret, "Failed to seal enclave data");

        // Give the caller a copy of the signing and encryption keys
        strncpy_s(outPublicEnclaveData, inAllocatedPublicEnclaveDataSize,
            enclaveData.get_public_data().c_str(),
            enclaveData.get_public_data_size());
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Error in pdo enclave(ecall_CreateEnclaveData): %04X -- %s",
            e.error_code(), e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Unknown error in pdo enclave(ecall_CreateEnclaveData)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}  // ecall_CreateEnclaveData

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_UnsealEnclaveData(const uint8_t* inSealedEnclaveData,
    size_t inSealedEnclaveDataSize,
    char* outPublicEnclaveData,
    size_t inAllocatedPublicEnclaveDataSize,
    size_t* outPublicEnclaveDataSize)
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        pdo::error::ThrowIfNull(inSealedEnclaveData, "SealedEnclaveData pointer is NULL");

        pdo::error::ThrowIfNull(outPublicEnclaveData, "Public enclave data pointer is NULL");
        pdo::error::ThrowIfNull(outPublicEnclaveDataSize, "Public data size pointer is NULL");

        (*outPublicEnclaveDataSize) = 0;
        Zero(outPublicEnclaveData, inAllocatedPublicEnclaveDataSize);

        // Unseal the enclave data
        EnclaveData enclaveData(inSealedEnclaveData);

        pdo::error::ThrowIf<pdo::error::ValueError>(
            inAllocatedPublicEnclaveDataSize < enclaveData.get_public_data_size(),
            "Public enclave data buffer size is too small");

        (*outPublicEnclaveDataSize) = enclaveData.get_public_data_size();

        // Give the caller a copy of the signing and encryption keys
        strncpy_s(outPublicEnclaveData, inAllocatedPublicEnclaveDataSize,
            enclaveData.get_public_data().c_str(),
            enclaveData.get_public_data_size());
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Error in pdo enclave(ecall_UnsealEnclaveData): %04X -- %s",
            e.error_code(), e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Unknown error in pdo enclave(ecall_UnsealEnclaveData)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}  // ecall_UnsealEnclaveData

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX Internal helper functions                                      XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void CreateSignupReportData(const char* pOriginatorPublicKeyHash,
    const EnclaveData& enclaveData,
    sgx_report_data_t* pReportData)
{
    // We will put the following in the report data SHA256(PPK|PEK|OPK_HASH)

    // WARNING - WARNING - WARNING - WARNING - WARNING - WARNING - WARNING
    //
    // If anything in this code changes the way in which the actual enclave
    // report data is represented, the corresponding code that verifies
    // the report data has to be change accordingly.
    //
    // WARNING - WARNING - WARNING - WARNING - WARNING - WARNING - WARNING
    std::string hashString;

    hashString.append(enclaveData.get_serialized_signing_key());
    hashString.append(enclaveData.get_serialized_encryption_key());

    // Canonicalize the originator public key hash string to ensure a consistent
    // format.
    std::transform(pOriginatorPublicKeyHash,
        pOriginatorPublicKeyHash + strlen(pOriginatorPublicKeyHash), std::back_inserter(hashString),
        [](char c) {
            return c;  // do nothing
        });

    // Now we put the SHA256 hash into the report data for the
    // report we will request.
    //
    // NOTE - we are putting the hash directly into the report
    // data structure because it is (64 bytes) larger than the SHA256
    // hash (32 bytes) but we zero it out first to ensure that it is
    // padded with known data.
    Zero(pReportData, sizeof(*pReportData));
    sgx_status_t ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(hashString.c_str()),
        static_cast<uint32_t>(hashString.size()),
        reinterpret_cast<sgx_sha256_hash_t*>(pReportData));
    pdo::error::ThrowSgxError(ret, "Failed to retrieve SHA256 hash of report data");
}  // CreateSignupReportData


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_CreateSealedSecret(size_t secret_len,
    uint8_t* outSealedSecret,
    size_t inAllocatedSealedSecretSize)
{

    pdo_err_t result = PDO_SUCCESS;

    try {
        pdo::error::ThrowIfNull(outSealedSecret, "outSealedSecret pointer is NULL");

        pdo::error::ThrowIf<pdo::error::ValueError>(
            inAllocatedSealedSecretSize < sgx_calc_sealed_data_size(0, secret_len),
            "SealedSecret data buffer size is too small");

        uint8_t* tmp = (uint8_t *) malloc(secret_len);

        sgx_status_t status = sgx_read_rand(tmp, secret_len);
        pdo::error::ThrowSgxError(status, "Failed to generate random key");

        // Seal up the enclave data into the caller's buffer.
        // NOTE - the attributes mask 0xfffffffffffffff3 seems rather
        // arbitrary, but according to SGX SDK documentation, this is
        // what sgx_seal_data uses, so it is good enough for us.
        sgx_attributes_t attribute_mask = {0xfffffffffffffff3, 0};
        status = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, attribute_mask,
            0,        // misc_mask
            0,        // additional mac text length
            nullptr,  // additional mac text
            secret_len,
            tmp,
            static_cast<uint32_t>(inAllocatedSealedSecretSize),
            reinterpret_cast<sgx_sealed_data_t*>(outSealedSecret));
        pdo::error::ThrowSgxError(status, "Failed to seal random key");

        memset_s(tmp, secret_len, 0, secret_len);
        free(tmp);
        tmp = NULL;
    }catch (pdo::error::Error& e) {
        Log(
            PDO_LOG_ERROR,
            "Error in pdo enclave(ecall_generate_key): %04X -- %s",
            e.error_code(),
            e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    } catch (...) {
        Log(
            PDO_LOG_ERROR,
            "Unknown error in pdo enclave(ecall_generate_key)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}  // ecall_CreateSealedSecret

pdo_err_t ecall_UnsealSecret(const uint8_t* inSealedSecret,
    size_t inSealedSecretSize,
    uint8_t* outPlainSecret,
    uint32_t inAllocatedPlainSecretSize)
{
    pdo_err_t result = PDO_SUCCESS;
    sgx_key_128bit_t key;

    try {
        pdo::error::ThrowIfNull(inSealedSecret, "SealedSecret pointer is NULL");

        pdo::error::ThrowIf<pdo::error::ValueError>(!sgx_is_within_enclave(inSealedSecret,sizeof(sgx_sealed_data_t)),
            "sgx_sealed_data_t members NOT in enclave");

        pdo::error::ThrowIf<pdo::error::ValueError>(
            inAllocatedPlainSecretSize < sgx_get_encrypt_txt_len(reinterpret_cast<const sgx_sealed_data_t*>(inSealedSecret)),
            "PlainSecret data buffer size is too small");

        // Unseal the data
        sgx_status_t status = sgx_unseal_data(reinterpret_cast<const sgx_sealed_data_t*>(inSealedSecret),
            nullptr, 0, outPlainSecret, &inAllocatedPlainSecretSize);
        pdo::error::ThrowSgxError(status, "Failed to unseal secret");

    }catch (pdo::error::Error& e) {
        Log(
            PDO_LOG_ERROR,
            "Error in pdo enclave(ecall_UnsealSecret): %04X -- %s",
            e.error_code(),
            e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    } catch (...) {
        Log(
            PDO_LOG_ERROR,
            "Unknown error in pdo enclave(ecall_UnsealSecret)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}// ecall_UnsealSecret



pdo_err_t ecall_GenerateEnclaveSecret(const uint8_t* inSealedEnclaveData,
    size_t inSealedEnclaveDataSize,
    const uint8_t* inSealedSecret,
    size_t inSealedSecretSize,
    const char* inEServiceEnclaveId,
    const char* inContractId,
    const char* inOpk,
    const char* inEnclaveEncryptKey,
    uint8_t* outSignedSecret,
    size_t inAllocatedSignedSecretSize)
{
    pdo_err_t result = PDO_SUCCESS;


    try {
        pdo::error::ThrowIfNull(inSealedEnclaveData, "Sealed enclave data pointer is NULL");
        pdo::error::ThrowIfNull(inSealedSecret, "Sealed Secret pointer is NULL");
        pdo::error::ThrowIfNull(inEServiceEnclaveId, "EService Enclave Id pointer is NULL");
        pdo::error::ThrowIfNull(inContractId, "Contract Id pointer is NULL");
        pdo::error::ThrowIfNull(inOpk, "Opk pointer is NULL");
        pdo::error::ThrowIfNull(inEnclaveEncryptKey, "Enclave Encrypt key pointer is NULL");
        pdo::error::ThrowIfNull(outSignedSecret, "Signed Secret pointer is NULL");

        pdo_err_t presult;

        //Unseal Secret
        uint32_t inAllocatedPlainSecretSize = sgx_get_encrypt_txt_len(reinterpret_cast<const sgx_sealed_data_t*>(inSealedSecret));

        ByteArray plainSecretBuffer(inAllocatedPlainSecretSize);
        ecall_UnsealSecret(inSealedSecret, inSealedSecretSize, plainSecretBuffer.data(), plainSecretBuffer.size());

        HexEncodedString plainSecret = ByteArrayToHexEncodedString(plainSecretBuffer);
        pdo::error::ThrowIf<pdo::error::ValueError>(
            plainSecret.length() < ENCODED_SECRET_SIZE,
            "secret is too short");

        pdo::error::ThrowIf<pdo::error::ValueError>(
            plainSecret.length() > ENCODED_SECRET_SIZE,
            "secret is too long");


        // Unseal the enclave persistent data
        EnclaveData enclaveData(inSealedEnclaveData);

        const std::string secret(plainSecret);
        const std::string eServiceEnclaveId(inEServiceEnclaveId);
        const std::string contractId(inContractId);
        const std::string opk(inOpk);
        const std::string enclaveEncryptKey(inEnclaveEncryptKey);

        ByteArray message;
        std::copy(secret.begin(), secret.end(), std::back_inserter(message));
        std::copy(eServiceEnclaveId.begin(), eServiceEnclaveId.end(), std::back_inserter(message));
        std::copy(contractId.begin(), contractId.end(), std::back_inserter(message));
        std::copy(opk.begin(), opk.end(), std::back_inserter(message));

        std::string msg = secret + eServiceEnclaveId + contractId + opk;
        SAFE_LOG(PDO_LOG_WARNING, "MESSAGE: <%s>\n", msg.c_str());

        const ByteArray signature = enclaveData.sign_message(message);

        HexEncodedString secretsig = ByteArrayToHexEncodedString(signature);

        int required_padding = 2 * SECRET_SIGNATURE_SIZE - secretsig.length();
        secretsig.append(required_padding,'0');

        pdo::error::ThrowIf<pdo::error::ValueError>(
            secretsig.length() < ENCODED_SECRET_SIGNATURE_SIZE,
            "secretsig is too short");

        pdo::error::ThrowIf<pdo::error::ValueError>(
            secretsig.length() > ENCODED_SECRET_SIGNATURE_SIZE,
            "secretsig is too long");

        ByteArray enclaveMessage;
        std::copy(secret.begin(), secret.end(), std::back_inserter(enclaveMessage));
        std::copy(secretsig.begin(), secretsig.end(), std::back_inserter(enclaveMessage));
        pdo::error::ThrowIf<pdo::error::ValueError>(
            enclaveMessage.size() < ENCODED_SECRET_SIZE + ENCODED_SECRET_SIGNATURE_SIZE,
            "enclaveMessage is too short");

        pdo::crypto::pkenc::PublicKey enclaveKey(enclaveEncryptKey);

        pdo::error::ThrowIf<pdo::error::ValueError>(
            enclaveMessage.size() < secret.length() + secretsig.length(),
            "enclaveMessage is too short");

        const ByteArray esecret = enclaveKey.EncryptMessage(enclaveMessage);

        Zero(outSignedSecret, inAllocatedSignedSecretSize);
        memcpy_s(outSignedSecret, inAllocatedSignedSecretSize, esecret.data(), esecret.size());

    }catch (pdo::error::Error& e) {
        Log(
            PDO_LOG_ERROR,
            "Error in pdo enclave(ecall_GenerateEnclaveSecret): %04X -- %s",
            e.error_code(),
            e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    } catch (...) {
        Log(
            PDO_LOG_ERROR,
            "Unknown error in pdo enclave(ecall_GenerateEnclaveSecret)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}// ecall_GenerateEnclaveSecret