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

#include <algorithm>
#include <string>
#include <vector>

#include "crypto.h"
#include "error.h"
#include "hex_string.h"
#include "log.h"
#include "pdo_error.h"
#include "types.h"

#include "enclave/enclave.h"
#include "enclave/base.h"

static bool g_IsInitialized = false;
static std::string g_LastError;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX External interface                                             XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int pdo::enclave_api::base::IsSgxSimulator()
{
#if defined(SGX_SIMULATOR)
    return 1;
#else // defined(SGX_SIMULATOR)
    return 0;
#endif // defined(SGX_SIMULATOR)
} // pdo::enclave_api::base::IsSgxSimulator

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void pdo::enclave_api::base::SetLastError(
    const std::string& message
    )
{
    g_LastError = message;
} // pdo::enclave_api::base::SetLastError

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::string pdo::enclave_api::base::GetLastError(void)
{
    return g_LastError;
} // pdo::enclave_api::base::GetLastErrorMessage

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::base::Initialize(
    const std::string& inPathToEnclave,
    const HexEncodedString& inSpid,
    pdo_log_t logFunction
    )
{
    pdo_err_t ret = PDO_SUCCESS;

    try {
        if (!g_IsInitialized)
        {
            pdo::SetLogFunction(logFunction);
            g_Enclave.SetSpid(inSpid);
            g_Enclave.Load(inPathToEnclave);
            g_IsInitialized = true;
        }
    } catch (pdo::error::Error& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        ret = e.error_code();
    } catch(std::exception& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        ret = PDO_ERR_UNKNOWN;
    } catch(...) {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        ret = PDO_ERR_UNKNOWN;
    }

    return ret;
} // pdo::enclave_api::base::Initialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::base::Terminate()
{
    // Unload the enclave
    pdo_err_t ret = PDO_SUCCESS;

    try {
        if (g_IsInitialized) {
            g_Enclave.Unload();
            g_IsInitialized = false;
        }
    } catch (pdo::error::Error& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        ret = PDO_ERR_UNKNOWN;
    } catch (...) {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        ret = PDO_ERR_UNKNOWN;
    }

    return ret;
} // pdo::enclave_api::base::Terminate

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t pdo::enclave_api::base::GetEnclaveQuoteSize()
{
    return g_Enclave.GetQuoteSize();
} // pdo::enclave_api::base::GetEnclaveQuoteSize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t pdo::enclave_api::base::GetSignatureSize()
{
    // this is the size of the byte array required for the signature
    // fixed constant for now until there is one we can get from the
    // crypto library
    return pdo::crypto::constants::MAX_SIG_SIZE;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::base::GetEpidGroup(
    HexEncodedString& outEpidGroup
    )
{
     pdo_err_t ret = PDO_SUCCESS;

     try {
        // Get the EPID group from the enclave and convert it to big endian
        sgx_epid_group_id_t epidGroup = { 0 };
        g_Enclave.GetEpidGroup(&epidGroup);

        std::reverse((uint8_t*)&epidGroup, (uint8_t*)&epidGroup + sizeof(epidGroup));

        // Convert the binary data to a hex string
        outEpidGroup = pdo::BinaryToHexString((const uint8_t*)&epidGroup, sizeof(epidGroup));
    } catch (pdo::error::Error& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        ret = PDO_ERR_UNKNOWN;
    } catch (...) {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        ret = PDO_ERR_UNKNOWN;
    }

    return ret;
} // pdo::enclave_api::base::GetEpidGroup

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::base::GetEnclaveCharacteristics(
    HexEncodedString& outMrEnclave,
    HexEncodedString& outEnclaveBasename
    )
{
    pdo_err_t ret = PDO_SUCCESS;

    try {
        // Get the enclave characteristics and then convert the binary data to
        // hex strings and copy them to the caller's buffers.
        sgx_measurement_t enclaveMeasurement;
        sgx_basename_t enclaveBasename;

        g_Enclave.GetEnclaveCharacteristics(
            &enclaveMeasurement,
            &enclaveBasename);

        outMrEnclave = pdo::BinaryToHexString(
            enclaveMeasurement.m,
            sizeof(enclaveMeasurement.m));

        outEnclaveBasename = pdo::BinaryToHexString(
            enclaveBasename.name,
            sizeof(enclaveBasename.name));

    } catch (pdo::error::Error& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        ret = PDO_ERR_UNKNOWN;
    } catch (...) {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        ret = PDO_ERR_UNKNOWN;
    }

    return ret;
} // pdo::enclave_api::base::GetEnclaveCharacteristics

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t pdo::enclave_api::base::SetSignatureRevocationList(
    const std::string& inSignatureRevocationList
    )
{
    pdo_err_t ret = PDO_SUCCESS;

    try {
        g_Enclave.SetSignatureRevocationList(inSignatureRevocationList);
    } catch (pdo::error::Error& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        ret = e.error_code();
    } catch (std::exception& e) {
        pdo::enclave_api::base::SetLastError(e.what());
        ret = PDO_ERR_UNKNOWN;
    } catch (...) {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        ret = PDO_ERR_UNKNOWN;
    }

    return ret;
} // pdo::enclave_api::base::SetSignatureRevocationList
