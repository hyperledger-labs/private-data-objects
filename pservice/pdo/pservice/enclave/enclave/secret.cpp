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

#include <algorithm>
#include <string>
#include <vector>

#include <sgx_uae_service.h>

#include "error.h"
#include "log.h"
#include "pdo_error.h"
#include "types.h"
#include "zero.h"

#include "enclave/enclave.h"
#include "enclave/base.h"
#include "enclave/secret.h"

#include "crypto.h"
namespace constants = pdo::crypto::constants;


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static size_t CalculateSealedEnclaveDataSize(void)
{
    size_t sealed_data_size;

    pdo_err_t presult = PDO_SUCCESS;
    sgx_status_t sresult;

    // get the enclave id for passing into the ecall
    sgx_enclave_id_t enclaveid = g_Enclave.GetEnclaveId();

    sresult =
        g_Enclave.CallSgx(
            [ enclaveid,
              &presult,
              &sealed_data_size ] ()
            {
                sgx_status_t ret =
                ecall_CalculateSealedEnclaveDataSize(
                    enclaveid,
                    &presult,
                    &sealed_data_size);
                return pdo::error::ConvertErrorStatus(ret, presult);
            });
    pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (ecall_CalculateSealedEnclaveDataSize)");
    g_Enclave.ThrowPDOError(presult);

    return sealed_data_size;
} // CalculateSealedEnclaveDataSize


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static size_t CalculatePublicEnclaveDataSize(void)
{
    size_t public_data_size;

    pdo_err_t presult = PDO_SUCCESS;
    sgx_status_t sresult;

    // get the enclave id for passing into the ecall
    sgx_enclave_id_t enclaveid = g_Enclave.GetEnclaveId();

    sresult =
        g_Enclave.CallSgx(
            [ enclaveid,
              &presult,
              &public_data_size ] ()
            {
                sgx_status_t ret =
                ecall_CalculatePublicEnclaveDataSize(
                    enclaveid,
                    &presult,
                    &public_data_size);
                return pdo::error::ConvertErrorStatus(ret, presult);
            });
    pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (ecall_CalculatePublicEnclaveDataSize)");
    g_Enclave.ThrowPDOError(presult);

    return public_data_size;
} // CalculatePublicEnclaveDataSize


static size_t CalculateSealedSecretSize(
    size_t plain_len
    )
{
    size_t sealed_secret_size;

    pdo_err_t presult = PDO_SUCCESS;
    sgx_status_t sresult;

    // get the enclave id for passing into the ecall
    sgx_enclave_id_t enclaveid = g_Enclave.GetEnclaveId();

    sresult =
        g_Enclave.CallSgx(
            [ enclaveid,
              &presult,
              plain_len,
              &sealed_secret_size ] ()
            {
                sgx_status_t ret =
                ecall_CalculateSealedSecretSize(
                    enclaveid,
                    &presult,
                    plain_len,
                    &sealed_secret_size);
                return pdo::error::ConvertErrorStatus(ret, presult);
            });
    pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (ecall_CalculateSealedSecretSize)");
    g_Enclave.ThrowPDOError(presult);

    return sealed_secret_size;
} // CalculateSealedEnclaveDataSize


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static uint32_t CalculatePlainSecretSize(
    const Base64EncodedString& inSealedSecret
    )
{

    ByteArray sealed_secret = Base64EncodedStringToByteArray(inSealedSecret);

    uint32_t plain_secret_size;

    pdo_err_t presult = PDO_SUCCESS;
    sgx_status_t sresult;

    // get the enclave id for passing into the ecall
    sgx_enclave_id_t enclaveid = g_Enclave.GetEnclaveId();

    sresult =
        g_Enclave.CallSgx(
            [ enclaveid,
              &presult,
              sealed_secret,
              &plain_secret_size ] ()
            {
                sgx_status_t ret =
                ecall_CalculatePlainSecretSize(
                    enclaveid,
                    &presult,
                    sealed_secret.data(),
                    sealed_secret.size(),
                    &plain_secret_size);
                return pdo::error::ConvertErrorStatus(ret, presult);
            });
    pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (ecall_CalculatePlainSecretSize)");
    g_Enclave.ThrowPDOError(presult);

    return plain_secret_size;
} // CalculatePlainSecretSize



// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::enclave_data::CreateEnclaveData(
    StringArray& outPublicEnclaveData,
    Base64EncodedString& outSealedEnclaveData,
    Base64EncodedString& outEnclaveQuote
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try {
        pdo_err_t presult;
        sgx_status_t sresult;

        outPublicEnclaveData.resize(CalculatePublicEnclaveDataSize());

        ByteArray sealed_enclave_data_buffer(CalculateSealedEnclaveDataSize());

        // get the enclave id for passing into the ecall
        sgx_enclave_id_t enclaveid = g_Enclave.GetEnclaveId();

        // We need target info in order to create signup data report
        sgx_target_info_t target_info = { 0 };
        sgx_epid_group_id_t epidGroupId = { 0 };

        sresult =
            g_Enclave.CallSgx(
                [&target_info,
                 &epidGroupId] () {
                    return sgx_init_quote(&target_info, &epidGroupId);
                });
        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (sgx_init_quote), failed to initialize the quote");

        // Properly size the sealed signup data buffer for the caller
        // and call into the enclave to create the signup data
        sgx_report_t enclave_report = { 0 };

        size_t computed_public_enclave_data_size;
        size_t computed_sealed_enclave_data_size;

        sresult = g_Enclave.CallSgx(
            [enclaveid,
             &presult,
             target_info,
             &outPublicEnclaveData,
             &computed_public_enclave_data_size,
             &sealed_enclave_data_buffer,
             &computed_sealed_enclave_data_size,
             &enclave_report ] ()
            {
                sgx_status_t ret = ecall_CreateEnclaveData(
                    enclaveid,
                    &presult,
                    &target_info,
                    outPublicEnclaveData.data(),
                    outPublicEnclaveData.size(),
                    &computed_public_enclave_data_size,
                    sealed_enclave_data_buffer.data(),
                    sealed_enclave_data_buffer.size(),
                    &computed_sealed_enclave_data_size,
                    &enclave_report);
                return pdo::error::ConvertErrorStatus(ret, presult);
            });
        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (ecall_CreateSignupData), failed to create signup data");
        g_Enclave.ThrowPDOError(presult);

        // reset the size of the public data
        outPublicEnclaveData.resize(computed_public_enclave_data_size);

        // reset the size of the enclave data and encode it
        sealed_enclave_data_buffer.resize(computed_sealed_enclave_data_size);
        outSealedEnclaveData = ByteArrayToBase64EncodedString(sealed_enclave_data_buffer);

        // take the report generated and create a quote for it, encode it
        size_t quote_size = pdo::enclave_api::base::GetEnclaveQuoteSize();
        ByteArray enclave_quote_buffer(quote_size);

    } catch (pdo::error::Error& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        result = e.error_code();
    } catch (std::exception& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        result = PDO_ERR_UNKNOWN;
    } catch (...) {
        pdo::enclave_api::base::SetLastError("Unexpected exception in (CreateEnclaveData)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
} // pdo::enclave_api::base::CreateSignupData

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::enclave_data::UnsealEnclaveData(
    const Base64EncodedString& inSealedEnclaveData,
    StringArray& outPublicEnclaveData
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try {
        ByteArray sealed_enclave_data = Base64EncodedStringToByteArray(inSealedEnclaveData);
        outPublicEnclaveData.resize(CalculatePublicEnclaveDataSize());

        // xxxxx call the enclave
        sgx_enclave_id_t enclaveid = g_Enclave.GetEnclaveId();

        // Call down into the enclave to unseal the signup data
        size_t computed_public_enclave_data_size;

        pdo_err_t presult = PDO_SUCCESS;
        sgx_status_t sresult = g_Enclave.CallSgx(
            [ enclaveid,
              &presult,
              sealed_enclave_data,
              &outPublicEnclaveData,
              &computed_public_enclave_data_size ] ()
            {
                sgx_status_t sresult =
                ecall_UnsealEnclaveData(
                    enclaveid,
                    &presult,
                    sealed_enclave_data.data(),
                    sealed_enclave_data.size(),
                    outPublicEnclaveData.data(),
                    outPublicEnclaveData.size(),
                    &computed_public_enclave_data_size);
                return pdo::error::ConvertErrorStatus(sresult, presult);
            });

        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (ecall_UnsealSignupData)");
        g_Enclave.ThrowPDOError(presult);

        outPublicEnclaveData.resize(computed_public_enclave_data_size);

    } catch (pdo::error::Error& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        result = e.error_code();
    } catch (std::exception& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        result = PDO_ERR_UNKNOWN;
    } catch (...) {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
} // pdo::enclave_api::base::UnsealSignupData



// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::enclave_data::CreateSealedSecret(
    const size_t secret_len,
    Base64EncodedString& outSealedSecret
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try {

        ByteArray sealed_enclave_secret_buffer(CalculateSealedSecretSize(secret_len));

        // xxxxx call the enclave
        sgx_enclave_id_t enclaveid = g_Enclave.GetEnclaveId();

        pdo_err_t presult = PDO_SUCCESS;
        sgx_status_t sresult = g_Enclave.CallSgx(
            [ enclaveid,
              &presult,
              secret_len,
              &sealed_enclave_secret_buffer] ()
            {
                sgx_status_t sresult =
                ecall_CreateSealedSecret(
                    enclaveid,
                    &presult,
                    secret_len,
                    sealed_enclave_secret_buffer.data(),
                    sealed_enclave_secret_buffer.size());
                return pdo::error::ConvertErrorStatus(sresult, presult);
            });
        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (ecall_CreateSealedSecret)");
        g_Enclave.ThrowPDOError(presult);

        outSealedSecret = ByteArrayToBase64EncodedString(sealed_enclave_secret_buffer);



    } catch (pdo::error::Error& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        result = e.error_code();
    } catch (std::exception& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        result = PDO_ERR_UNKNOWN;
    } catch (...) {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
} // pdo::enclave_api::base::CreateSealedSecret


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::enclave_data::UnsealSecret(
    const Base64EncodedString& inSealedSecret,
    HexEncodedString& outPlainSecret
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try {
        ByteArray sealed_secret = Base64EncodedStringToByteArray(inSealedSecret);

        ByteArray plain_secret_buffer(CalculatePlainSecretSize(inSealedSecret));

        // xxxxx call the enclave
        sgx_enclave_id_t enclaveid = g_Enclave.GetEnclaveId();

        pdo_err_t presult = PDO_SUCCESS;
        sgx_status_t sresult = g_Enclave.CallSgx(
            [ enclaveid,
              &presult,
              sealed_secret,
              &plain_secret_buffer] ()
            {
                sgx_status_t sresult =
                ecall_UnsealSecret(
                    enclaveid,
                    &presult,
                    sealed_secret.data(),
                    sealed_secret.size(),
                    plain_secret_buffer.data(),
                    plain_secret_buffer.size());
                return pdo::error::ConvertErrorStatus(sresult, presult);
            });

        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (ecall_UnsealSecret)");
        g_Enclave.ThrowPDOError(presult);

        outPlainSecret = ByteArrayToHexEncodedString(plain_secret_buffer);
            } catch (pdo::error::Error& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        result = e.error_code();
    } catch (std::exception& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        result = PDO_ERR_UNKNOWN;
    } catch (...) {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
} // pdo::enclave_api::base::UnsealSecret

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::enclave_data::GenerateEnclaveSecret(
        const Base64EncodedString& inSealedEnclaveData,
        const Base64EncodedString& inSealedSecret,
        const std::string& inContractId,
        const std::string& inOpk,
        const std::string& inEnclaveInfo,
        Base64EncodedString& ouSignedSecret
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try {

        ByteArray sealed_enclave_data = Base64EncodedStringToByteArray(inSealedEnclaveData);
        ByteArray sealed_secret = Base64EncodedStringToByteArray(inSealedSecret);
        ByteArray signature_buffer(constants::RSA_KEY_SIZE >> 3);

        // xxxxx call the enclave
        sgx_enclave_id_t enclaveid = g_Enclave.GetEnclaveId();

        pdo_err_t presult = PDO_SUCCESS;
        sgx_status_t sresult = g_Enclave.CallSgx(
            [ enclaveid,
              &presult,
              sealed_enclave_data,
              sealed_secret,
              inContractId,
              inOpk,
              inEnclaveInfo,
              &signature_buffer] ()
            {
                sgx_status_t sresult =
                ecall_GenerateEnclaveSecret(
                    enclaveid,
                    &presult,
                    sealed_enclave_data.data(),
                    sealed_enclave_data.size(),
                    sealed_secret.data(),
                    sealed_secret.size(),
                    inContractId.c_str(),
                    inOpk.c_str(),
                    inEnclaveInfo.c_str(),
                    signature_buffer.data(),
                    signature_buffer.size());
                return pdo::error::ConvertErrorStatus(sresult, presult);
            });

        pdo::error::ThrowSgxError(sresult, "SGX enclave call failed (ecall_GenerateEnclaveSecret)");
        g_Enclave.ThrowPDOError(presult);

        ouSignedSecret = ByteArrayToBase64EncodedString(signature_buffer);

    } catch (pdo::error::Error& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        result = e.error_code();
    } catch (std::exception& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        result = PDO_ERR_UNKNOWN;
    } catch (...) {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
} // pdo::enclave_api::base::GenerateEnclaveSecret
