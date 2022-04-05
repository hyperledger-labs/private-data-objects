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
static pdo::enclave_queue::EnclaveQueue *g_EnclaveReadyQueue;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX External interface                                             XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int pdo::enclave_api::base::IsSgxSimulator()
{
#if defined(SGX_SIMULATOR)
#if SGX_SIMULATOR == 1
    return 1;
#else // SGX_SIMULATOR not 1
    return 0;
#endif //  #if SGX_SIMULATOR == 1
#else // SGX_SIMULATOR not defined
    return 0;
#endif // defined(SGX_SIMULATOR)
} // pdo::enclave_api::base::IsSgxSimulator


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo::enclave_queue::ReadyEnclave pdo::enclave_api::base::GetReadyEnclave()
{
    return pdo::enclave_queue::ReadyEnclave(g_EnclaveReadyQueue);
} // pdo::enclave_api::base::GetReadyEnclaveIndex


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
    const int numOfEnclaves
    )
{
    pdo_err_t ret = PDO_SUCCESS;

    try {
        if (!g_IsInitialized)
        {

            if (g_EnclaveReadyQueue == NULL) g_EnclaveReadyQueue = new pdo::enclave_queue::EnclaveQueue();

            g_Enclave.reserve(numOfEnclaves);
            for (int i = 0; i < numOfEnclaves; ++i)
            {
                g_Enclave.push_back(pdo::enclave_api::Enclave());
                g_EnclaveReadyQueue->push(i);
            }

            for (pdo::enclave_api::Enclave& enc : g_Enclave)
            {
                enc.SetSpid(inSpid);
                enc.Load(inPathToEnclave);
                enc.StartWorker();
            }

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
            for (pdo::enclave_api::Enclave& enc : g_Enclave) {
                enc.ShutdownWorker();
                enc.Unload();
            }
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
pdo_err_t pdo::enclave_api::base::ShutdownWorkers()
{
    // Unload the enclave
    pdo_err_t ret = PDO_SUCCESS;

    try {
        if (g_IsInitialized) {
            for (pdo::enclave_api::Enclave& enc : g_Enclave) {
                enc.ShutdownWorker();
            }
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
} // pdo::enclave_api::base::ShutdownWorkers

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t pdo::enclave_api::base::GetEnclaveQuoteSize()
{
    return g_Enclave[0].GetQuoteSize();
} // pdo::enclave_api::base::GetEnclaveQuoteSize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
size_t pdo::enclave_api::base::GetSignatureMaxSize()
{
    // this is the size of the byte array required for the signature
    // fixed constant for now until there is one we can get from the
    // crypto library

    // Note:
    // while making a call to the crypto library would be beneficial,
    // this would raise the following challenge in the PDO build.
    // As this function is used in eservice/pdo/eservice/enclave/enclave/contract.cpp,
    // this would create a direct dependency between this file
    // (eservice/pdo/eservice/enclave/enclave/contract.cpp) and the crypto library (including openssl).
    // This is a problem because the _pdo_enclave_internal.cpython-38-x86_64-linux-gnu.so library
    // (built through eservice/setup.py) uses the mentioned cpp file, but depends neither on crypto nor openssl.
    // Those dependencies are all confined in the _crypto.cpython-38-x86_64-linux-gnu.so library
    // (built through python/setup.py).
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
        g_Enclave[0].GetEpidGroup(&epidGroup);

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

        g_Enclave[0].GetEnclaveCharacteristics(
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
        g_Enclave[0].SetSignatureRevocationList(inSignatureRevocationList);
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
