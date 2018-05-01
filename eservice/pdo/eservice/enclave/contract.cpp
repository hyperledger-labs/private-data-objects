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

#include <stdlib.h>
#include <string>
#include <map>

#include "error.h"
#include "pdo_error.h"
#include "swig_utils.h"
#include "types.h"

#include "contract.h"

#include "enclave/base.h"
#include "enclave/contract.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::map<std::string, std::string> contract_verify_secrets(
    const std::string& sealed_signup_data,
    const std::string& contract_id,
    const std::string& contract_creator_id,
    const std::string& serialized_secret_list
    )
{
    Base64EncodedString encrypted_contract_key_buffer;
    Base64EncodedString signature_buffer;

    pdo_err_t presult = pdo::enclave_api::contract::VerifySecrets(
        sealed_signup_data,
        contract_id,
        contract_creator_id,
        serialized_secret_list,
        encrypted_contract_key_buffer,
        signature_buffer);
    ThrowPDOError(presult);

    std::map<std::string, std::string> result;
    result["encrypted_state_encryption_key"] = encrypted_contract_key_buffer;
    result["signature"] = signature_buffer;

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::string contract_handle_contract_request(
    const std::string& sealed_signup_data,
    const std::string& encrypted_session_key,
    const std::string& serialized_request
    )
{
    pdo_err_t presult;

    uint32_t response_identifier;
    size_t response_size;

    presult = pdo::enclave_api::contract::HandleContractRequest(
        sealed_signup_data,
        encrypted_session_key,
        serialized_request,
        response_identifier,
        response_size);
    ThrowPDOError(presult);

    Base64EncodedString response;
    presult = pdo::enclave_api::contract::GetSerializedResponse(
        sealed_signup_data,
        response_identifier,
        response_size,
        response);
    ThrowPDOError(presult);

    return response;
}
