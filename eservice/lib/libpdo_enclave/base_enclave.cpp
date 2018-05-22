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
#include <sgx_tae_service.h>  //sgx_time_t, sgx_time_source_nonce_t, sgx_get_trusted_time
#include <sgx_tcrypto.h>
#include <sgx_tkey_exchange.h>
#include <sgx_trts.h>
#include <sgx_utils.h>  // sgx_get_key, sgx_create_report

#include "auto_handle_sgx.h"

#include "error.h"
#include "pdo_error.h"
#include "zero.h"

#include "base_enclave.h"
#include "enclave_utils.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// ECDSA public key generated. Note the 8 magic bytes are removed and
// x and y component are changed to little endian . The public key is hard coded in the enclave
// DRD generated public key
static const sgx_ec256_public_t g_sp_pub_key = {
    {0xC0, 0x8C, 0x9F, 0x45, 0x59, 0x1A, 0x9F, 0xAE, 0xC5, 0x1F, 0xBC, 0x3E, 0xFB, 0x4F, 0x67, 0xB1,
        0x93, 0x61, 0x45, 0x9E, 0x30, 0x27, 0x10, 0xC4, 0x92, 0x0F, 0xBB, 0xB2, 0x69, 0xB0, 0x16,
        0x39},
    {0x5D, 0x98, 0x6B, 0x24, 0x2B, 0x52, 0x46, 0x72, 0x2A, 0x35, 0xCA, 0xE0, 0xA9, 0x1A, 0x6A, 0xDC,
        0xB8, 0xEB, 0x32, 0xC8, 0x1C, 0x2B, 0x5A, 0xF1, 0x23, 0x1F, 0x6C, 0x6E, 0x30, 0x00, 0x96,
        0x4F}};

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

