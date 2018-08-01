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

#include <stdlib.h>

#include <cctype>
#include <iterator>

#include <sgx_key.h>
#include <sgx_tcrypto.h>
#include <sgx_trts.h>
#include <sgx_utils.h>  // sgx_get_key, sgx_create_report

#include "auto_handle_sgx.h"

#include "error.h"
#include "pdo_error.h"
#include "zero.h"

#include "base_enclave.h"
#include "enclave_utils.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XX External interface                                             XX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
/*
This ecall is a wrapper of sgx_ra_init to create the trusted
KE exchange key context needed for the remote attestation
SIGMA API's. Input pointers aren't checked since the trusted stubs
copy them into EPC memory.

@param p_context Pointer to the location where the returned key
    context is to be copied.
@return Any error returned during the initialization process.
*/
pdo_err_t ecall_Initialize()
{
    pdo_err_t result = PDO_SUCCESS;

    // we need to make sure we print a warning if the logging is turned on
    // since it can break confidentiality of contract execution
    SAFE_LOG(PDO_LOG_CRITICAL, "enclave initialized with debugging turned on");

    return result;
}  // ecall_Initialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t ecall_CreateErsatzEnclaveReport(sgx_target_info_t* targetInfo, sgx_report_t* outReport)
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        pdo::error::ThrowIfNull(targetInfo, "targetInfo is not valid");
        pdo::error::ThrowIfNull(outReport, "outReport is not valid");

        Zero(outReport, sizeof(*outReport));

        // Create a relatively useless enclave report.  Well....the report
        // itself is not useful for anything except that it can be used to
        // create SGX quotes, which contain potentially useful information
        // (like the enclave basename, mr_enclave, etc.).
        pdo::error::ThrowSgxError(
            sgx_create_report(targetInfo, nullptr, outReport), "Failed to create report.");
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "Error in pdo enclave(ecall_CreateErsatzEnclaveReport): %04X "
            "-- %s",
            e.error_code(), e.what());
        ocall_SetErrorMessage(e.what());
        result = e.error_code();
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Unknown error in pdo enclave(ecall_CreateErsatzEnclaveReport)");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}  // ecall_CreateErsatzEnclaveReport
