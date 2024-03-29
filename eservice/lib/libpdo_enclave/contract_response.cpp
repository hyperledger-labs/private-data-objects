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

#include <map>
#include <string>
#include <vector>

#include "error.h"
#include "pdo_error.h"

#include "crypto.h"
#include "jsonvalue.h"
#include "packages/base64/base64.h"
#include "parson.h"
#include "interpreter_kv.h"
#include "types.h"

#include "enclave_utils.h"

#include "contract_request.h"
#include "contract_response.h"
#include "enclave_data.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// See ${PDO_SOURCE_ROOT}/eservice/docs/contract.json for format
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractResponse::ContractResponse(
    const ContractRequest& request,
    const bool operation_succeeded,
    const std::string& result)
    : result_(result), operation_succeeded_(operation_succeeded)
{
    contract_id_ = request.contract_id_;
    creator_id_ = request.creator_id_;
    channel_verifying_key_ = request.contract_message_.channel_verifying_key_;
    contract_code_hash_ = request.contract_code_.code_hash_;
    contract_message_hash_ = request.contract_message_.message_hash_;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray ContractResponse::ComputeSignature(const EnclaveData& enclave_data) const
{
    ByteArray serialized;
    SerializeForSigning(serialized);

    return enclave_data.sign_message(serialized);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractResponse::SerializeForSigning(ByteArray& serialized) const
{
    std::copy(
        channel_verifying_key_.begin(),
        channel_verifying_key_.end(),
        std::back_inserter(serialized));

    std::copy(
        contract_id_.begin(),
        contract_id_.end(),
        std::back_inserter(serialized));

    std::copy(
        contract_code_hash_.begin(),
        contract_code_hash_.end(),
        std::back_inserter(serialized));

    std::copy(
        contract_message_hash_.begin(),
        contract_message_hash_.end(),
        std::back_inserter(serialized));
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray ContractResponse::SerializeAndEncrypt(
    const ByteArray& session_key, const EnclaveData& enclave_data) const
{
    // Create the response structure
    JsonValue contract_response_value(json_value_init_object());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !contract_response_value.value, "Failed to create the response object");

    JSON_Object* contract_response_object = json_value_get_object(contract_response_value);
    pdo::error::ThrowIfNull(
        contract_response_object, "Failed on retrieval of response object value");

    // Use alphabetical order for the keys to ensure predictable
    // serialization
    JSON_Status jret;

    // --------------- status ---------------
    jret = json_object_dotset_boolean(contract_response_object, "Status", operation_succeeded_);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the status");

    // --------------- result ---------------
    jret = json_object_dotset_string(contract_response_object, "InvocationResponse", result_.c_str());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the result");

    // serialize the resulting json
    size_t serializedSize = json_serialization_size(contract_response_value);
    ByteArray serialized_response;
    serialized_response.resize(serializedSize);

    jret = json_serialize_to_buffer(contract_response_value,
        reinterpret_cast<char*>(&serialized_response[0]), serialized_response.size());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "contract response serialization failed");

    ByteArray encrypted_response =
        pdo::crypto::skenc::EncryptMessage(session_key, serialized_response);

    return encrypted_response;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
InitializeStateResponse::InitializeStateResponse(
    const InitializeStateRequest& request,
    const pdo::state::StateBlockId& output_block_id,
    const ByteArray& metadata_hash,
    const std::string& result) :
    ContractResponse(request, true, result),
    contract_metadata_hash_(metadata_hash),
    output_block_id_(output_block_id)
{
    SAFE_LOG(PDO_LOG_DEBUG,
             "output state hash: %s",
             ByteArrayToHexEncodedString(output_block_id_).c_str());
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void InitializeStateResponse::SerializeForSigning(
    ByteArray& serialized) const
{
    ContractResponse::SerializeForSigning(serialized);

    std::copy(
        creator_id_.begin(),
        creator_id_.end(),
        std::back_inserter(serialized));

    std::copy(
        contract_metadata_hash_.begin(),
        contract_metadata_hash_.end(),
        std::back_inserter(serialized));

    std::copy(
        output_block_id_.begin(),
        output_block_id_.end(),
        std::back_inserter(serialized));
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray InitializeStateResponse::SerializeAndEncrypt(
    const ByteArray& session_key, const EnclaveData& enclave_data) const
{
    // Create the response structure
    JsonValue contract_response_value(json_value_init_object());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !contract_response_value.value, "Failed to create the response object");

    JSON_Object* contract_response_object = json_value_get_object(contract_response_value);
    pdo::error::ThrowIfNull(
        contract_response_object, "Failed on retrieval of response object value");

    // Use alphabetical order for the keys to ensure predictable
    // serialization
    JSON_Status jret;

    // --------------- status ---------------
    jret = json_object_dotset_boolean(contract_response_object, "Status", operation_succeeded_);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the status");

    // --------------- result ---------------
    jret = json_object_dotset_string(contract_response_object, "InvocationResponse", result_.c_str());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the result");

    // --------------- signature ---------------
    ByteArray signature = ComputeSignature(enclave_data);
    Base64EncodedString encoded_signature = base64_encode(signature);

    jret = json_object_dotset_string(contract_response_object, "Signature", encoded_signature.c_str());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the signature");

    // --------------- state ---------------
    std::string value;

    value = base64_encode(contract_metadata_hash_);
    jret = json_object_dotset_string(contract_response_object, "MetadataHash", value.c_str());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the metadata hash");

    value = base64_encode(output_block_id_);
    jret = json_object_dotset_string(contract_response_object, "StateHash", value.c_str());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the state hash");

    // serialize the resulting json
    size_t serializedSize = json_serialization_size(contract_response_value);
    ByteArray serialized_response;
    serialized_response.resize(serializedSize);

    jret = json_serialize_to_buffer(contract_response_value,
        reinterpret_cast<char*>(&serialized_response[0]), serialized_response.size());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "contract response serialization failed");

    ByteArray encrypted_response =
        pdo::crypto::skenc::EncryptMessage(session_key, serialized_response);

    return encrypted_response;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
UpdateStateResponse::UpdateStateResponse(
    const UpdateStateRequest& request,
    const pdo::state::StateBlockId& input_block_id,
    const pdo::state::StateBlockId& output_block_id,
    const std::map<std::string, std::string>& dependencies,
    const std::string& result) :
    ContractResponse(request, true, result),
    state_changed_(true),
    input_block_id_(input_block_id),
    output_block_id_(output_block_id),
    dependencies_(dependencies)
{
    SAFE_LOG(PDO_LOG_DEBUG,
             "input state hash: %s",
             ByteArrayToHexEncodedString(input_block_id_).c_str());
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
UpdateStateResponse::UpdateStateResponse(
    const UpdateStateRequest& request,
    const pdo::state::StateBlockId& input_block_id,
    const std::string& result) :
    ContractResponse(request, true, result),
    state_changed_(false),
    input_block_id_(input_block_id),
    output_block_id_(input_block_id)
{
    SAFE_LOG(PDO_LOG_DEBUG,
             "input state hash: %s",
             ByteArrayToHexEncodedString(input_block_id_).c_str());
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void UpdateStateResponse::SerializeForSigning(
    ByteArray& serialized) const
{
    ContractResponse::SerializeForSigning(serialized);

    std::copy(
        input_block_id_.begin(),
        input_block_id_.end(),
        std::back_inserter(serialized));

    std::copy(
        output_block_id_.begin(),
        output_block_id_.end(),
        std::back_inserter(serialized));

    std::map<std::string, std::string>::const_iterator iter;
    for (iter = dependencies_.begin(); iter != dependencies_.end(); iter++)
    {
        std::copy(iter->first.begin(), iter->first.end(), std::back_inserter(serialized));
        std::copy(iter->second.begin(), iter->second.end(), std::back_inserter(serialized));
    }

#if PDO_DEBUG_BUILD
    SAFE_LOG(PDO_LOG_DEBUG, "contract id: %s", contract_id_.c_str());
    SAFE_LOG(PDO_LOG_DEBUG, "creator id: %s", creator_id_.c_str());

    std::string debug_contract_hash = ByteArrayToBase64EncodedString(contract_code_hash_);
    SAFE_LOG(PDO_LOG_DEBUG, "contract_code_hash: %s", debug_contract_hash.c_str());

    std::string debug_message_hash = ByteArrayToBase64EncodedString(contract_message_hash_);
    SAFE_LOG(PDO_LOG_DEBUG, "contract_message_hash: %s", debug_message_hash.c_str());

    std::string debug_old_state_hash = ByteArrayToBase64EncodedString(input_block_id_);
    SAFE_LOG(PDO_LOG_DEBUG, "old state hash: %s", debug_old_state_hash.c_str());

    std::string debug_state_hash = ByteArrayToBase64EncodedString(output_block_id_);
    SAFE_LOG(PDO_LOG_DEBUG, "new state hash: %s", debug_state_hash.c_str());

    std::string debug_xxx = ByteArrayToBase64EncodedString(serialized);
    SAFE_LOG(PDO_LOG_DEBUG, "serialized contract response message: %s", debug_xxx.c_str());

    std::string debug_mhash = ByteArrayToBase64EncodedString(pdo::crypto::ComputeMessageHash(serialized));
    SAFE_LOG(PDO_LOG_DEBUG, "serialized contract response message has length %d and hash %s",
        serialized.size(), debug_mhash.c_str());
#endif
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray UpdateStateResponse::SerializeAndEncrypt(
    const ByteArray& session_key, const EnclaveData& enclave_data) const
{
    // Create the response structure
    JsonValue contract_response_value(json_value_init_object());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !contract_response_value.value, "Failed to create the response object");

    JSON_Object* contract_response_object = json_value_get_object(contract_response_value);
    pdo::error::ThrowIfNull(
        contract_response_object, "Failed on retrieval of response object value");

    // Use alphabetical order for the keys to ensure predictable
    // serialization
    JSON_Status jret;

    // --------------- status ---------------
    jret = json_object_dotset_boolean(contract_response_object, "Status", operation_succeeded_);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the status");

    // --------------- state updated ---------------
    jret = json_object_dotset_boolean(contract_response_object, "StateChanged", state_changed_);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the state_changed");

    // --------------- result ---------------
    jret = json_object_dotset_string(contract_response_object, "InvocationResponse", result_.c_str());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the result");

    if (operation_succeeded_ && state_changed_) {
        // --------------- signature ---------------
        ByteArray signature = ComputeSignature(enclave_data);
        Base64EncodedString encoded_signature = base64_encode(signature);

        jret =
            json_object_dotset_string(contract_response_object, "Signature", encoded_signature.c_str());
        pdo::error::ThrowIf<pdo::error::RuntimeError>(
            jret != JSONSuccess, "failed to serialize the signature");

        // --------------- state ---------------
        jret = json_object_dotset_string(contract_response_object, "StateHash", base64_encode(output_block_id_).c_str());
        pdo::error::ThrowIf<pdo::error::RuntimeError>(
            jret != JSONSuccess, "failed to serialize the state hash");

        // --------------- dependencies ---------------
        jret = json_object_set_value(contract_response_object, "Dependencies", json_value_init_array());
        pdo::error::ThrowIf<pdo::error::RuntimeError>(
            jret != JSONSuccess, "failed to serialize the dependencies");

        JSON_Array* dependency_array = json_object_get_array(contract_response_object, "Dependencies");
        pdo::error::ThrowIfNull(dependency_array, "failed to serialize the dependency array");

        std::map<std::string, std::string>::const_iterator it;
        for (it = dependencies_.begin(); it != dependencies_.end(); it++)
        {
            JSON_Value* dependency_value = json_value_init_object();
            pdo::error::ThrowIfNull(dependency_value, "failed to create a dependency array");

            JSON_Object* dependency_object = json_value_get_object(dependency_value);
            pdo::error::ThrowIfNull(dependency_object, "failed to create a dependency value");

            jret = json_object_dotset_string(dependency_object, "ContractID", it->first.c_str());
            pdo::error::ThrowIf<pdo::error::RuntimeError>(
                jret != JSONSuccess, "failed to serialize contract id in the dependency list");

            jret = json_object_dotset_string(dependency_object, "StateHash", it->second.c_str());
            pdo::error::ThrowIf<pdo::error::RuntimeError>(
                jret != JSONSuccess, "failed to serialize contract hash in the dependency list");

            jret = json_array_append_value(dependency_array, dependency_value);
            pdo::error::ThrowIf<pdo::error::RuntimeError>(
                jret != JSONSuccess, "failed to add dependency to the serialization array");
        }
    }

    // serialize the resulting json
    size_t serializedSize = json_serialization_size(contract_response_value);
    ByteArray serialized_response;
    serialized_response.resize(serializedSize);

    jret = json_serialize_to_buffer(contract_response_value,
        reinterpret_cast<char*>(&serialized_response[0]), serialized_response.size());
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        jret != JSONSuccess, "contract response serialization failed");

    ByteArray encrypted_response =
        pdo::crypto::skenc::EncryptMessage(session_key, serialized_response);

    return encrypted_response;
}
