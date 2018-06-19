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

#include <iostream>
#include <vector>

#include "error.h"
#include "pdo_error.h"
#include "swig_utils.h"
#include "types.h"

#include "enclave/base.h"
#include "enclave_info.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool is_sgx_simulator()
{
    return 0 != pdo::enclave_api::base::IsSgxSimulator();
} // _is_sgx_simulator

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_enclave_info::pdo_enclave_info(
    const std::string& enclaveModulePath,
    const std::string& spid
    )
{
    PyLog(PDO_LOG_INFO, "Initializing SGX PDO enclave");
    PyLogV(PDO_LOG_DEBUG, "Enclave path: %s", enclaveModulePath.c_str());
    PyLogV(PDO_LOG_DEBUG, "SPID: %s", spid.c_str());

    pdo_err_t ret = pdo::enclave_api::base::Initialize(
        enclaveModulePath,
        spid,
        PyLog
        );
    ThrowPDOError(ret);
    PyLog(PDO_LOG_INFO, "SGX PDO enclave initialized.");

    HexEncodedString mrEnclaveBuffer;
    HexEncodedString basenameBuffer;

    ThrowPDOError(
        pdo::enclave_api::base::GetEnclaveCharacteristics(
            mrEnclaveBuffer,
            basenameBuffer));

    this->mr_enclave = mrEnclaveBuffer;
    this->basename = basenameBuffer;

} // pdo_enclave_info::pdo_enclave_info

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_enclave_info::~pdo_enclave_info()
{
    try
    {
        pdo::enclave_api::base::Terminate();
        TerminateInternal();
    }
    catch (...)
    {}

} // pdo_enclave_info::~pdo_enclave_info

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::string pdo_enclave_info::get_epid_group()
{
    HexEncodedString epidGroupBuffer;
    ThrowPDOError(
        pdo::enclave_api::base::GetEpidGroup(epidGroupBuffer));

    return epidGroupBuffer;
} // pdo_enclave_info::get_epid_group

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void pdo_enclave_info::set_signature_revocation_list(
    const std::string& signature_revocation_list
    )
{
    ThrowPDOError(
        pdo::enclave_api::base::SetSignatureRevocationList(signature_revocation_list));

} // pdo_enclave_info::set_signature_revocation_lists
