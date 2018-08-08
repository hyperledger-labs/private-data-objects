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

#include "error.h"
#include "pdo_error.h"
#include "types.h"

#include "crypto.h"
#include "jsonvalue.h"
#include "parson.h"

#include "contract_request.h"
#include "contract_response.h"
#include "contract_secrets.h"

#include "enclave_utils.h"
#include "interpreter/ContractInterpreter.h"
#include "interpreter/CppProcessor.h"
#ifdef INTKEY_CPP_CONTRACT_TEST
#include "interpreter/cpp_processor/CppProcessorHandler.h"
#else
#include "interpreter/gipsy_scheme/GipsyInterpreter.h"
#endif

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Request format for create and send methods
//
// {
//     "Operation" : "<string>",
//     "ContractID" : "<string>",
//     "CreatorID" : "<string>",
//     "EncryptedStateEncryptionKey" : "<base64 encoded encrypted state encryption key>",
//     "Contract" :
//     {
//         "Code" : "<string>",
//         "Name" : "<string>"
//         "Nonce" : "<string>"
//     },
//     "Message" :
//     {
//         "Expression" : "<string>",
//         "OriginatorPublicKey" : "<serialized verifying key>",
//         "ChannelPublicKey" : "<serialized verifying key>",
//         "Nonce" : "<string>",
//         "Signature" : "<base64 encoded signature>"
//     },
//     "ContractState" :
//     {
//         "EncryptedState" : ""
//     }
// }
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractRequest::ContractRequest(
        const ByteArray& session_key, const ByteArray& encrypted_request)
{
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

    pvalue = json_object_dotget_string(request_object, "CreatorID");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve CreatorID");
    creator_id_.assign(pvalue);

    // state encryption key
    pvalue = json_object_dotget_string(request_object, "EncryptedStateEncryptionKey");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve EncryptedStateEncryptionKey");

    state_encryption_key_ = DecodeAndDecryptStateEncryptionKey(contract_id_, pvalue);

    // contract code
    ovalue = json_object_dotget_object(request_object, "ContractCode");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve ContractCode");
    contract_code_.Unpack(ovalue);

    // contract state
    ovalue = json_object_dotget_object(request_object, "ContractState");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !ovalue, "invalid request; failed to retrieve ContractState");

    ByteArray id_hash = Base64EncodedStringToByteArray(contract_id_);
    pdo::error::ThrowIf<pdo::error::ValueError>(
        id_hash.size() != SHA256_DIGEST_LENGTH, "invalid contract id");

    contract_state_.Unpack(state_encryption_key_, ovalue, id_hash, contract_code_.ComputeHash());

    // contract message
    ovalue = json_object_dotget_object(request_object, "ContractMessage");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve ContractMessage");
    contract_message_.Unpack(ovalue);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractResponse ContractRequest::process_initialization_request(void)
{
    // the only reason for the try/catch here is to provide some logging for the error
    try
    {
#ifdef INTKEY_CPP_CONTRACT_TEST
        CppProcessor interpreter;
#else
        GipsyInterpreter interpreter;
#endif

        pdo::contracts::ContractCode code;
        code.Code = contract_code_.code_;
        code.Name = contract_code_.name_;

        pdo::contracts::ContractMessage msg;
        msg.Message = contract_message_.expression_;
        msg.OriginatorID = contract_message_.originator_verifying_key_;

        pdo::contracts::ContractState new_contract_state;
        std::map<string, string> dependencies;

        interpreter.create_initial_contract_state(
            contract_id_, creator_id_, code, msg, new_contract_state);

        ByteArray new_state(new_contract_state.State.begin(), new_contract_state.State.end());
        ContractResponse response(*this, dependencies, new_state, "");

        return response;
    }
    catch (pdo::error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "failed initialization for contract %s: %s",
            contract_code_.name_.c_str(), e.what());

        ByteArray error_state(0);
        std::map<string, string> dependencies;
        ContractResponse response(*this, dependencies, error_state, e.what());
        response.operation_succeeded_ = false;
        return response;
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "exception while processing update for contract %s with message %s: %s",
            contract_code_.name_.c_str(), contract_message_.expression_.c_str(), e.what());

        ByteArray error_state(0);
        std::map<string, string> dependencies;
        ContractResponse response(*this, dependencies, error_state, "internal error");
        response.operation_succeeded_ = false;
        return response;
    }
#ifdef INTKEY_CPP_CONTRACT_TEST
    catch (IntKeyCppContractWrapperException& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "failed inside IntkeyContractWrapper %s: %s",
            contract_code_.name_.c_str(), e.what());

        ByteArray error_state(0);
        std::map<string, string> dependencies;
        ContractResponse response(*this, dependencies, error_state, e.what());
        response.operation_succeeded_ = false;
        return response;
    }
#endif
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "unknown exception while processing initialization request");

        ByteArray error_state(0);
        std::map<string, string> dependencies;
        ContractResponse response(*this, dependencies, error_state, "unknown internal error");
        response.operation_succeeded_ = false;
        return response;
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractResponse ContractRequest::process_update_request(void)
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
#ifdef INTKEY_CPP_CONTRACT_TEST
        CppProcessor interpreter;
#else
        GipsyInterpreter interpreter;
#endif

        pdo::contracts::ContractCode code;
        code.Code = contract_code_.code_;
        code.Name = contract_code_.name_;

        pdo::contracts::ContractMessage msg;
        msg.Message = contract_message_.expression_;
        msg.OriginatorID = contract_message_.originator_verifying_key_;

        pdo::contracts::ContractState current_contract_state;
        current_contract_state.StateHash =
            ByteArrayToBase64EncodedString(contract_state_.state_hash_);
        current_contract_state.State = ByteArrayToString(contract_state_.decrypted_state_);

        pdo::contracts::ContractState new_contract_state;
        std::map<string, string> dependencies;
        std::string result;

        interpreter.send_message_to_contract(contract_id_, creator_id_, code, msg,
            current_contract_state, new_contract_state, dependencies, result);

        // check for operations that did not modify state
        if (new_contract_state.State.empty())
        {
            ByteArray empty_state(0);
            std::map<string, string> dependencies;
            ContractResponse response(*this, dependencies, empty_state, result);
            response.state_changed_ = false;
            return response;
        }
        else
        {
            ByteArray new_state(new_contract_state.State.begin(), new_contract_state.State.end());
            ContractResponse response(*this, dependencies, new_state, result);
            return response;
        }
    }
    catch (pdo::error::ValueError& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "failed update for contract %s with message %s: %s",
            contract_code_.name_.c_str(), contract_message_.expression_.c_str(), e.what());

        ByteArray error_state(0);
        std::map<string, string> dependencies;
        ContractResponse response(*this, dependencies, error_state, e.what());
        response.operation_succeeded_ = false;
        return response;
    }
    catch (pdo::error::Error& e)
    {
        SAFE_LOG(PDO_LOG_ERROR,
            "exception while processing update for contract %s with message %s: %s",
            contract_code_.name_.c_str(), contract_message_.expression_.c_str(), e.what());

        ByteArray error_state(0);
        std::map<string, string> dependencies;
        ContractResponse response(*this, dependencies, error_state, "internal error");
        response.operation_succeeded_ = false;
        return response;
    }
#ifdef INTKEY_CPP_CONTRACT_TEST
    catch (IntKeyCppContractWrapperException& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "failed inside IntkeyContractWrapper %s: %s",
            contract_code_.name_.c_str(), e.what());

        ByteArray error_state(0);
        std::map<string, string> dependencies;
        ContractResponse response(*this, dependencies, error_state, e.what());
        response.operation_succeeded_ = false;
        return response;
    }
#endif
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "unknown exception while processing update request");

        ByteArray error_state(0);
        std::map<string, string> dependencies;
        ContractResponse response(*this, dependencies, error_state, "unknown internal error");
        response.operation_succeeded_ = false;
        return response;
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractResponse ContractRequest::process_request(void)
{
    switch (operation_)
    {
        case op_initialize:
            return process_initialization_request();

        case op_update:
            return process_update_request();

        default:
            throw pdo::error::ValueError("unknown operation");
    }
}
