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

#include <unistd.h>
#include <ctype.h>

#include <exception>
#include <string>
#include <map>

#include "packages/base64/base64.h"
#include "packages/parson/parson.h"

#include "basic_kv.h"
#include "crypto.h"
#include "error.h"
#include "log.h"
#include "pdo_error.h"
#include "types.h"

#include "InvocationHelpers.h"

namespace pc = pdo::contracts;
namespace pe = pdo::error;
namespace pstate = pdo::state;

#define KW(kw,v) "\"" #kw "\":" #v

#define DEPENDENCY "[{" KW(ContractID,"") "," KW(StateHash,"") "}]"
#define DEPENDENCIES "\"Dependencies\":" DEPENDENCY

#define INVOCATION_REQUEST_SCHEMA "{" KW(Method,"") ","  KW(PositionalParameters,[]) "," KW(KeywordParameters,{}) "}"
#define INVOCATION_RESPONSE_SCHEMA "{" KW(Status,true) "," KW(Response,null) "," KW(StateChanged,true) "," DEPENDENCIES "}"

// -----------------------------------------------------------------
// validate_invocation_request
// -----------------------------------------------------------------
void pc::validate_invocation_request(
    const string& request)
{
    JsonValue schema(json_parse_string(INVOCATION_REQUEST_SCHEMA));
    JsonValue parsed(json_parse_string(request.c_str()));
    pe::ThrowIf<pe::RuntimeError>(
        json_validate(schema.value, parsed.value) != JSONSuccess,
        "invalid invocation request; does not match required format");
}

// -----------------------------------------------------------------
// parse_invocation_response
// -----------------------------------------------------------------
void pc::parse_invocation_response(
    const std::string& response,
    std::string& outResponse,
    bool& outStatus,
    bool& outStateChanged,
    std::map<std::string,std::string>& outDependencies)
{
    // Parse the contract request
    JsonValue parsed(json_parse_string(response.c_str()));
    pe::ThrowIfNull(parsed.value, "invalid response string; invalid JSON");

    // Verify that the response matches the expected schema
    JsonValue schema(json_parse_string(INVOCATION_RESPONSE_SCHEMA));
    pe::ThrowIf<pe::RuntimeError>(
        json_validate(schema.value, parsed.value) != JSONSuccess,
        "invalid invocation response; does not match required format");

    const JSON_Object* parsed_object = json_value_get_object(parsed);
    pe::ThrowIfNull(
        parsed_object,
        "invalid result pointer; missing result object");

    // response
    const JSON_Value* response_value = json_object_get_value(parsed_object, "Response");
    pe::ThrowIfNull(response_value, "invalid response string; missing Response field");

    size_t serialized_size = json_serialization_size(response_value);
    ByteArray serialized_response_value;
    serialized_response_value.resize(serialized_size);
    JSON_Status jret = json_serialize_to_buffer(
        response_value,
        reinterpret_cast<char*>(&serialized_response_value[0]),
        serialized_response_value.size());
    pe::ThrowIf<pe::RuntimeError>(
        jret != JSONSuccess,
        "failed to serialize result");
    outResponse = ByteArrayToString(serialized_response_value);

    // dependencies
    const JSON_Array *dependency_array = json_object_dotget_array(parsed_object, "Dependencies");
    pe::ThrowIfNull(dependency_array, "invalid response string; missing Dependencies field");

    size_t dependency_count = json_array_get_count(dependency_array);
    for (size_t i = 0; i < dependency_count; i++)
    {
        const JSON_Object* dependency = json_array_get_object(dependency_array, i);
        const char* contract_id = json_object_dotget_string(dependency, "ContractID");
        const char* state_hash = json_object_dotget_string(dependency, "StateHash");
        outDependencies[contract_id] = state_hash;
    }

    // status
    outStatus = (json_object_dotget_boolean(parsed_object, "Status") == 1);

    // state changed
    outStateChanged = (json_object_dotget_boolean(parsed_object, "StateChanged") == 1);
}

// -----------------------------------------------------------------
// create_invocation_environment
// -----------------------------------------------------------------
void pc::create_invocation_environment(
    const std::string& ContractID,
    const std::string& CreatorID,
    const pc::ContractCode& inContractCode,
    const pc::ContractMessage& inMessage,
    const pstate::StateBlockId& inContractStateHash,
    std::string& outEnvironment
    )
{
    JsonValue contract_environment(json_value_init_object());
    pe::ThrowIf<pe::RuntimeError>(
        !contract_environment.value, "Failed to create the contract environment");

    JSON_Object* contract_environment_object = json_value_get_object(contract_environment);
    pe::ThrowIfNull(
        contract_environment_object, "Failed on retrieval of response object value");

    JSON_Status jret;

    jret = json_object_dotset_string(contract_environment_object, "ContractID", ContractID.c_str());
    pe::ThrowIf<pe::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the ContractID");

    jret = json_object_dotset_string(contract_environment_object, "CreatorID", CreatorID.c_str());
    pe::ThrowIf<pe::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the CreatorID");

    jret = json_object_dotset_string(contract_environment_object, "OriginatorID", inMessage.OriginatorID.c_str());
    pe::ThrowIf<pe::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the OriginatorID");

    //the hash is the hash of the encrypted state, in our case it's the root hash given in input
    const Base64EncodedString state_hash = ByteArrayToBase64EncodedString(inContractStateHash);

    jret = json_object_dotset_string(contract_environment_object, "StateHash", state_hash.c_str());
    pe::ThrowIf<pe::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the StateHash");

    jret = json_object_dotset_string(contract_environment_object, "MessageHash", inMessage.MessageHash.c_str());
    pe::ThrowIf<pe::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the MessageHash");

    jret = json_object_dotset_string(contract_environment_object, "ContractCodeName", inContractCode.Name.c_str());
    pe::ThrowIf<pe::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the ContractCodeName");

    jret = json_object_dotset_string(contract_environment_object, "ContractCodeHash", inContractCode.CodeHash.c_str());
    pe::ThrowIf<pe::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the ContractCodeName");

    // serialize the resulting json
    size_t serializedSize = json_serialization_size(contract_environment);
    StringArray serialized_response(serializedSize);

    jret = json_serialize_to_buffer(contract_environment,
          reinterpret_cast<char*>(&serialized_response[0]), serialized_response.size());

    pe::ThrowIf<pe::RuntimeError>(
        jret != JSONSuccess, "contract response serialization failed");

    outEnvironment = serialized_response.str();
}
