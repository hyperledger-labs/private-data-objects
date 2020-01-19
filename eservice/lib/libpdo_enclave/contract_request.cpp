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
#include <exception>

#include "error.h"
#include "pdo_error.h"
#include "types.h"

#include "crypto.h"
#include "jsonvalue.h"
#include "parson.h"

#include "contract_worker.h"
#include "contract_request.h"
#include "contract_response.h"
#include "contract_secrets.h"

#include "enclave_utils.h"

#include "interpreter_kv.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// See ${PDO_SOURCE_ROOT}/eservice/docs/contract.json for format
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractRequest::ContractRequest(
    const ByteArray& session_key,
    const ByteArray& encrypted_request,
    ContractWorker* worker)
{
    worker_ = worker;

    JSON_Object* ovalue = nullptr;

    ByteArray decrypted_request =
        pdo::crypto::skenc::DecryptMessage(session_key, encrypted_request);
    std::string request = ByteArrayToString(decrypted_request);

    // Parse the contract request
    JsonValue parsed(json_parse_string(request.c_str()));
    pdo::error::ThrowIfNull(
        parsed.value, "failed to parse the contract request, badly formed JSON");

    JSON_Object* request_object = json_value_get_object(parsed);
    pdo::error::ThrowIfNull(request_object, "Missing JSON object in contract request");

    // operation
    const char* pvalue = json_object_dotget_string(request_object, "Operation");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve contract operation");
    std::string svalue(pvalue);

    if (svalue == "initialize")
        operation_ = op_initialize;
    else if (svalue == "update")
        operation_ = op_update;
    else
        throw pdo::error::ValueError("unknown operation requested");

    // contract information
    pvalue = json_object_dotget_string(request_object, "ContractID");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve ContractID");
    contract_id_.assign(pvalue);

    contract_id_hash_ = Base64EncodedStringToByteArray(contract_id_);
    pdo::error::ThrowIf<pdo::error::ValueError>(
        contract_id_hash_.size() != SHA256_DIGEST_LENGTH,
        "invalid contract id");

    pvalue = json_object_dotget_string(request_object, "CreatorID");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve CreatorID");
    creator_id_.assign(pvalue);

    // state encryption key
    pvalue = json_object_dotget_string(request_object, "EncryptedStateEncryptionKey");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve EncryptedStateEncryptionKey");

    state_encryption_key_ = DecodeAndDecryptStateEncryptionKey(contract_id_, pvalue);

    if (operation_ == op_initialize)
    {
        // contract code
        ovalue = json_object_dotget_object(request_object, "ContractCode");
        pdo::error::ThrowIf<pdo::error::ValueError>(
            !pvalue, "invalid request; failed to retrieve ContractCode");
        contract_code_.Unpack(ovalue);
    }
    else
    {
        // contract code hash
        pvalue = json_object_dotget_string(request_object, "ContractCodeHash");
        pdo::error::ThrowIf<pdo::error::ValueError>(
            !pvalue, "invalid request; failed to retrieve ContractCodeHash");

        code_hash_ = Base64EncodedStringToByteArray(pvalue);
        pdo::error::ThrowIf<pdo::error::ValueError>(
            code_hash_.size() != SHA256_DIGEST_LENGTH,
            "invalid contract code hash");

        // contract state hash
        pvalue = json_object_dotget_string(request_object, "ContractStateHash");
        pdo::error::ThrowIf<pdo::error::ValueError>(
            !pvalue, "invalid request; failed to retrieve ContractStateHash");

        input_state_hash_ = Base64EncodedStringToByteArray(pvalue);
        pdo::error::ThrowIf<pdo::error::ValueError>(
            input_state_hash_.size() != SHA256_DIGEST_LENGTH,
            "invalid contract state hash");
    }

    // contract message
    ovalue = json_object_dotget_object(request_object, "ContractMessage");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve ContractMessage");
    contract_message_.Unpack(ovalue);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractResponse ContractRequest::process_initialization_request(ContractState& contract_state)
{
    // the only reason for the try/catch here is to provide some logging for the error
    try
    {
        pdo::contracts::ContractCode code;
        code.Code = contract_code_.code_;
        code.Name = contract_code_.name_;
        code.CodeHash = ByteArrayToBase64EncodedString(contract_code_.code_hash_);

        pdo::contracts::ContractMessage msg;
        msg.Message = contract_message_.expression_;
        msg.OriginatorID = contract_message_.originator_verifying_key_;
        msg.MessageHash = ByteArrayToBase64EncodedString(contract_message_.message_hash_);

        std::map<std::string, std::string> dependencies;

        // Push this into a block to ensure that the interpreter is deallocated
        // and frees its memory before finalizing the state update
        {
            // this class ensures that the interpreter is released on exit
            InitializedInterpreter interpreter(worker_);

            SAFE_LOG(PDO_LOG_DEBUG, "KV id before interpreter: %s\n",
                     ByteArrayToHexEncodedString(contract_state.input_block_id_).c_str());

            interpreter.interpreter_->create_initial_contract_state(
                contract_id_, creator_id_, code, msg, contract_state.state_);
        }

        contract_state.Finalize();
        ContractResponse response(*this, contract_state, dependencies, "", contract_state.output_block_id_);

        return response;
    }
    catch (pdo::error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
                 "value error during initialization of contract %s: %s",
                 contract_code_.name_.c_str(),
                 e.what());

        ContractResponse response(*this, contract_state, e.what());
        return response;
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
                 "PDO exception while initializing contract %s with message %s: %s",
                 contract_code_.name_.c_str(),
                 contract_message_.expression_.c_str(),
                 e.what());

        ContractResponse response(*this, contract_state, "internal pdo error");
        return response;
    }
    catch(std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
                 "standard exception while initializing contract %s with message %s: %s",
                 contract_code_.name_.c_str(),
                 contract_message_.expression_.c_str(),
                 e.what());

        ContractResponse response(*this, contract_state, "internal error");
        return response;
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractResponse ContractRequest::process_update_request(ContractState& contract_state)
{
    /*
       NOTE: for operations that do not modify state, either because the
       operation fails or because the operation is informational only, we
       do not return the new state. this design prefers performance (the gains
       from not requiring encryption, presentation formating, or signing) over
       confidentiality since some information can be inferred from the size of
       the response message.
    */

    // the only reason for the try/catch here is to provide some logging for the error
    try
    {
        pdo::contracts::ContractCode code;
        code.Code = contract_code_.code_;
        code.Name = contract_code_.name_;
        code.CodeHash = ByteArrayToBase64EncodedString(contract_code_.code_hash_);

        pdo::contracts::ContractMessage msg;
        msg.Message = contract_message_.expression_;
        msg.OriginatorID = contract_message_.originator_verifying_key_;
        msg.MessageHash = ByteArrayToBase64EncodedString(contract_message_.message_hash_);

        std::map<std::string, std::string> dependencies;
        std::string result;

        bool state_changed_flag;

        // Push this into a block to ensure that the interpreter is deallocated
        // and frees its memory before finalizing the state update
        {
            InitializedInterpreter interpreter(worker_);

            SAFE_LOG(PDO_LOG_DEBUG, "KV id before interpreter: %s\n",
                     ByteArrayToHexEncodedString(contract_state.input_block_id_).c_str());

            interpreter.interpreter_->send_message_to_contract(
                contract_id_,
                creator_id_,
                code, msg,
                contract_state.input_block_id_,
                contract_state.state_,
                state_changed_flag,
                dependencies,
                result);
        }

        contract_state.Finalize();

        // check for operations that did not modify state
        if (state_changed_flag)
        {
            ContractResponse response(*this, contract_state, dependencies, result, contract_state.output_block_id_);
            return response;
        }
        else
        {
            // since the state is unchanged, we can just use the input block id as the output block id
            std::map<std::string, std::string> dependencies;
            ContractResponse response(*this, contract_state, dependencies, result, contract_state.input_block_id_);

            response.state_changed_ = false;
            return response;
        }
    }
    catch (pdo::error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
                 "value error while updating contract %s with message %s: %s",
                 contract_code_.name_.c_str(),
                 contract_message_.expression_.c_str(),
                 e.what());

        contract_state.Finalize();

        pdo::state::StateBlockId output_block_id(STATE_BLOCK_ID_LENGTH, 0);
        std::map<std::string, std::string> dependencies;
        ContractResponse response(*this, contract_state, dependencies, e.what(), output_block_id);
        response.operation_succeeded_ = false;
        return response;
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
                 "PDO exception while updating contract %s with message %s: %s",
                 contract_code_.name_.c_str(),
                 contract_message_.expression_.c_str(),
                 e.what());

        ContractResponse response(*this, contract_state, "internal pdo error");
        return response;
    }
    catch(std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
                 "standard exception while updating contract %s with message %s: %s",
                 contract_code_.name_.c_str(),
                 contract_message_.expression_.c_str(),
                 e.what());

        ContractResponse response(*this, contract_state, "internal error");
        return response;
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractResponse ContractRequest::process_request(ContractState& contract_state)
{
    switch (operation_)
    {
        case op_initialize:
            return process_initialization_request(contract_state);

        case op_update:
            return process_update_request(contract_state);

        default:
            throw pdo::error::ValueError("unknown operation");
    }
}
