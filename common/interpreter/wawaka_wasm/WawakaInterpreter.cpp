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

#include "WawakaInterpreter.h"

namespace pc = pdo::contracts;
namespace pe = pdo::error;
namespace pstate = pdo::state;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
const std::string WawakaInterpreter::identity_ = "wawaka";

std::string pdo::contracts::GetInterpreterIdentity(void)
{
    return WawakaInterpreter::identity_;
}

pc::ContractInterpreter* pdo::contracts::CreateInterpreter(void)
{
    return new WawakaInterpreter();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// function definitions for the Wasm interpreter
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern "C" {
#include "wasm_export.h"
#include "bh_memory.h"
#include "bh_common.h"

//#include "sample.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void wasm_logger(unsigned int level, const char *msg, const int value)
{
    SAFE_LOG(level, "%s; %d", msg, value);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void wasm_printer(const char *msg)
{
    SAFE_LOG(PDO_LOG_ERROR, msg);
}

} /* extern "C" */

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void WawakaInterpreter::parse_result_string(
    int32 result_app,
    std::string& outResult,
    bool& outStateChanged)
{
    int32 result_app_beg, result_app_end;

    pe::ThrowIf<pe::RuntimeError>(
        ! wasm_runtime_get_app_addr_range(wasm_module_inst, result_app, &result_app_beg, &result_app_end),
        report_interpreter_error("invalid result pointer", "out of range"));

    char *result = (char*)wasm_runtime_addr_app_to_native(wasm_module_inst, result_app);
    const char *result_end = result + (result_app_end - result_app);

    for (char *p = result; (*p) != '\0'; p++)
        pe::ThrowIf<pe::RuntimeError>(
            p == result_end,
            report_interpreter_error("invalid result pointer", "unterminated string"));

    // Parse the contract request
    JsonValue parsed(json_parse_string(result));
    pe::ThrowIfNull(
        parsed.value,
        report_interpreter_error("invalid result pointer", "invalid JSON"));

    JSON_Object* parsed_object = json_value_get_object(parsed);
    pe::ThrowIfNull(
        parsed_object,
        report_interpreter_error("invalid result pointer", "missing result object"));

    outResult.assign(json_object_dotget_string(parsed_object, "Result"));
    outStateChanged = (json_object_dotget_boolean(parsed_object, "StateChanged") == 1);

    int status = json_object_dotget_boolean(parsed_object, "Status");
    pe::ThrowIf<pe::ValueError>(
        status < 1,
        report_interpreter_error("operation failed", outResult.c_str()));
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Create the JSON encoded environment for passing into the contract
// method
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static void create_environment_string(
    const std::string& ContractID,
    const std::string& CreatorID,
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

    jret = json_object_dotset_string(contract_environment_object, "MessageID", inMessage.OriginatorID.c_str());
    pe::ThrowIf<pe::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the CreatorID");

    //the hash is the hash of the encrypted state, in our case it's the root hash given in input
    const Base64EncodedString state_hash = ByteArrayToBase64EncodedString(inContractStateHash);

    jret = json_object_dotset_string(contract_environment_object, "StateHash", state_hash.c_str());
    pe::ThrowIf<pe::RuntimeError>(
        jret != JSONSuccess, "failed to serialize the StateHash");

    // serialize the resulting json
    size_t serializedSize = json_serialization_size(contract_environment);
    StringArray serialized_response(serializedSize);

    jret = json_serialize_to_buffer(contract_environment,
          reinterpret_cast<char*>(&serialized_response[0]), serialized_response.size());

    pe::ThrowIf<pe::RuntimeError>(
        jret != JSONSuccess, "contract response serialization failed");

    outEnvironment = serialized_response.str();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
const char* WawakaInterpreter::report_interpreter_error(
    const char* message,
    const char* error)
{
    error_msg_ = message;
    error_msg_.append("; ");
    error_msg_.append(error);
    return error_msg_.c_str();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void WawakaInterpreter::load_contract_code(
    const std::string& code)
{
    char error_buf[128];
    ByteArray binary_code = Base64EncodedStringToByteArray(code);

    wasm_module = wasm_runtime_load((uint8*)binary_code.data(), binary_code.size(), error_buf, sizeof(error_buf));
    if (wasm_module == NULL)
        SAFE_LOG(PDO_LOG_CRITICAL, "load failed with error <%s>", error_buf);

    pe::ThrowIfNull(wasm_module, "module load failed");

    wasm_module_inst = wasm_runtime_instantiate(wasm_module, 64*1024, 64*1024, error_buf, sizeof(error_buf));
    pe::ThrowIfNull(wasm_module_inst, "failed to instantiate the module");

    /* this would allow specific stack size, just use the default for now */
    wasm_exec_env = wasm_runtime_create_exec_env(1024 * 64);
    pe::ThrowIfNull(wasm_exec_env, "failed to create the wasm execution environment");
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// current expects marshalled data
int32 WawakaInterpreter::evaluate_function(
    const std::string& args,
    const std::string& env)
{
    char *buffer;
    wasm_function_inst_t wasm_func = NULL;

    wasm_func = wasm_runtime_lookup_function(wasm_module_inst, "_dispatch", "(i32i32)i32");
    pe::ThrowIfNull(wasm_func, "Unable to locate the dispatch function");

    // might need to add a null terminator
    uint32 argv[2];
    argv[0] = (int32)wasm_runtime_module_malloc(wasm_module_inst, args.length() + 1);
    argv[1] = (int32)wasm_runtime_module_malloc(wasm_module_inst, env.length() + 1);

    buffer = (char*)wasm_runtime_addr_app_to_native(wasm_module_inst, argv[0]);
    memcpy(buffer, args.c_str(), args.length());
    buffer[args.length()] = '\0';

    buffer = (char*)wasm_runtime_addr_app_to_native(wasm_module_inst, argv[1]);
    memcpy(buffer, env.c_str(), env.length());
    buffer[env.length()] = '\0';

    if (! wasm_runtime_call_wasm(wasm_module_inst, wasm_exec_env, wasm_func, 2, argv)) {
        SAFE_LOG(PDO_LOG_ERROR, "execution failed for some reason");

        const char *exception = wasm_runtime_get_exception(wasm_module_inst);
        if (exception != NULL)
            SAFE_LOG(PDO_LOG_ERROR, "exception=%s", exception);

        return 0;
    }

    SAFE_LOG(PDO_LOG_DEBUG, "RESULT=%u", argv[0]);
    return argv[0];
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void WawakaInterpreter::Finalize(void)
{
    // Destroy the environment
    if (wasm_exec_env != NULL)
    {
        wasm_runtime_destroy_exec_env(wasm_exec_env);
        wasm_exec_env = NULL;
    }

    if (wasm_module_inst != NULL)
    {
        wasm_runtime_deinstantiate(wasm_module_inst);
        wasm_module_inst = NULL;
    }

    if (wasm_module != NULL)
    {
        wasm_runtime_unload(wasm_module);
        wasm_module = NULL;
    }

    wasm_runtime_destroy();
    bh_memory_destroy();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
WawakaInterpreter::~WawakaInterpreter(void)
{
    Finalize();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void WawakaInterpreter::Initialize(void)
{
    int result;

    SAFE_LOG(PDO_LOG_DEBUG, "initialize wasm interpreter");

    bh_set_print_function(wasm_printer);

    result = bh_memory_init_with_pool(global_heap_buf, sizeof(global_heap_buf));
    pe::ThrowIf<pe::RuntimeError>(result != 0, "failed to initialize wasm interpreter memory ppol");

    wasm_runtime_init();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
WawakaInterpreter::WawakaInterpreter(void)
{
    Initialize();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void WawakaInterpreter::create_initial_contract_state(
    const std::string& ContractID,
    const std::string& CreatorID,
    const pc::ContractCode& inContractCode,
    const pc::ContractMessage& inMessage,
    pstate::Basic_KV_Plus& inoutContractState
    )
{
    pstate::StateBlockId initialStateHash;
    initialStateHash.assign(initialStateHash.size(), 0); // this is probably not necessary

    // load the contract code
    load_contract_code(inContractCode.Code);

    // this doesn't really set thread local data since it is
    // not supported for sgx, it does however attach the data
    // to the module so we can use it in the extensions
    wasm_runtime_set_custom_data(wasm_module_inst, (void*)&inoutContractState);

    // serialize the environment parameter for the method
    std::string env;
    create_environment_string(ContractID, CreatorID, inMessage, initialStateHash, env);

    // invoke the initialize function, later we can allow this to be passed with args
    const std::string message("{\"method\" : \"initialize\"}");
    int32 result_app = evaluate_function(message, env);

    std::string outMessageResult;
    bool outStateChangedFlag;
    parse_result_string(result_app, outMessageResult, outStateChangedFlag);

    // this should be in finally... later...
    wasm_runtime_set_custom_data(wasm_module_inst, NULL);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void WawakaInterpreter::send_message_to_contract(
    const std::string& ContractID,
    const std::string& CreatorID,
    const pc::ContractCode& inContractCode,
    const pc::ContractMessage& inMessage,
    const pstate::StateBlockId& inContractStateHash,
    pstate::Basic_KV_Plus& inoutContractState,
    bool& outStateChangedFlag,
    std::map<std::string,std::string>& outDependencies,
    std::string& outMessageResult
    )
{
    // initialize the extensions library with the current state

    // load the contract code
    load_contract_code(inContractCode.Code);

    // this doesn't really set thread local data since it is
    // not supported for sgx, it does however attach the data
    // to the module so we can use it in the extensions
    wasm_runtime_set_custom_data(wasm_module_inst, (void*)&inoutContractState);

    // serialize the environment parameter for the method
    std::string env;
    create_environment_string(ContractID, CreatorID, inMessage, inContractStateHash, env);

    int32 result_app = evaluate_function(inMessage.Message, env);
    parse_result_string(result_app, outMessageResult, outStateChangedFlag);

    // this should be in finally... later...
    wasm_runtime_set_custom_data(wasm_module_inst, NULL);
}

// syntax of the response expected from the contract method
// {
//     "Status" : bool,
//     "StateChanged" : bool,
//     "Result" : string,
//     "Dependencies" : [
//         {
//             "ContractID" : string,
//             "StateHash" : string
//         }
//     ]
// }
