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
#include <vector>

// This is for the uint64_t formats for the log statements
#include <inttypes.h>

#include "error.h"
#include "log.h"
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

    pdo::enclave_queue::ReadyEnclave readyEnclave = pdo::enclave_api::base::GetReadyEnclave();

    pdo_err_t presult = pdo::enclave_api::contract::VerifySecrets(
        sealed_signup_data,
        contract_id,
        contract_creator_id,
        serialized_secret_list,
        encrypted_contract_key_buffer,
        signature_buffer,
        readyEnclave.getIndex());
    ThrowPDOError(presult);

    std::map<std::string, std::string> result;
    result["encrypted_state_encryption_key"] = encrypted_contract_key_buffer;
    result["signature"] = signature_buffer;

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Base64EncodedString contract_handle_contract_encoded_request(
    const std::string& sealed_signup_data,
    const Base64EncodedString& encrypted_session_key,
    const Base64EncodedString& serialized_request
    )
{
    ByteArray decoded_key = Base64EncodedStringToByteArray(encrypted_session_key);
    ByteArray decoded_request = Base64EncodedStringToByteArray(serialized_request);

    ByteArray response_array = contract_handle_contract_request(sealed_signup_data, decoded_key, decoded_request);

    return ByteArrayToBase64EncodedString(response_array);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::vector<uint8_t> contract_handle_contract_request(
    const std::string& sealed_signup_data,
    const std::vector<uint8_t>& encrypted_session_key,
    const std::vector<uint8_t>& serialized_request
    )
{
    pdo_err_t presult;

    uint32_t response_identifier;
    size_t response_size;

#if PDO_DEBUG_BUILD
    uint64_t start_time = GetTimer();
    uint64_t request_identifier = GetRequestIdentifier();
    SAFE_LOG(PDO_LOG_DEBUG, "start request [%" PRIu64 "]", request_identifier);
#endif

    pdo::enclave_queue::ReadyEnclave readyEnclave = pdo::enclave_api::base::GetReadyEnclave();

    presult = pdo::enclave_api::contract::HandleContractRequest(
        sealed_signup_data,
        encrypted_session_key,
        serialized_request,
        response_identifier,
        response_size,
        readyEnclave.getIndex());
    ThrowPDOError(presult);

    std::vector<uint8_t> response(response_size);
    presult = pdo::enclave_api::contract::GetSerializedResponse(
        sealed_signup_data,
        response_identifier,
        response_size,
        response,
        readyEnclave.getIndex());
    ThrowPDOError(presult);

    SAFE_LOG(PDO_LOG_DEBUG, "end request [%" PRIu64 "]; elapsed time %" PRIu64, request_identifier, GetTimer() - start_time);

    return response;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::vector<uint8_t> initialize_contract_state(
    const std::string& sealed_signup_data,
    const std::vector<uint8_t>& encrypted_session_key,
    const std::vector<uint8_t>& serialized_request
    )
{
    pdo_err_t presult;

    uint32_t response_identifier;
    size_t response_size;

#if PDO_DEBUG_BUILD
    uint64_t start_time = GetTimer();
    uint64_t request_identifier = GetRequestIdentifier();
    SAFE_LOG(PDO_LOG_DEBUG, "start request [%" PRIu64 "]", request_identifier);
#endif

    pdo::enclave_queue::ReadyEnclave readyEnclave = pdo::enclave_api::base::GetReadyEnclave();

    presult = pdo::enclave_api::contract::InitializeContractState(
        sealed_signup_data,
        encrypted_session_key,
        serialized_request,
        response_identifier,
        response_size,
        readyEnclave.getIndex());
    ThrowPDOError(presult);

    std::vector<uint8_t> response(response_size);
    presult = pdo::enclave_api::contract::GetSerializedResponse(
        sealed_signup_data,
        response_identifier,
        response_size,
        response,
        readyEnclave.getIndex());
    ThrowPDOError(presult);

    SAFE_LOG(PDO_LOG_DEBUG, "end request [%" PRIu64 "]; elapsed time %" PRIu64, request_identifier, GetTimer() - start_time);

    return response;
}
