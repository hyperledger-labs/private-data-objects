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

#pragma once

#include <string>
#include <map>

#include "basic_kv.h"
#include "ContractInterpreter.h"

extern "C" {
#include "wasm_export.h"
#include "bh_platform.h"
}

namespace pc = pdo::contracts;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class WawakaInterpreter : public pc::ContractInterpreter
{
private:
    std::string error_msg_;

    char global_heap_buf[10 * 1024 * 1024] = { 0 };
    wasm_module_t wasm_module = NULL;
    wasm_module_inst_t wasm_module_inst = NULL;
    wasm_exec_env_t wasm_exec_env = NULL;
    ByteArray binary_code_;

    void parse_response_string(
        int32 response_app,
        std::string& outResult,
        bool& outStateChanged,
        std::map<string,string>& outDependencies);

    const char* report_interpreter_error(
        const char* message,
        const char* error);

    void load_contract_code(
        const std::string& code);

    int32 initialize_contract(
        const std::string& env);

    int32 evaluate_function(
        const std::string& args,
        const std::string& env);

public:
    // Identity of the interpreter returned in enclave information
    static const std::string identity_;

    void create_initial_contract_state(
        const std::string& ContractID,
        const std::string& CreatorID,
        const pc::ContractCode& inContractCode,
        const pc::ContractMessage& inMessage,
        pdo::state::Basic_KV_Plus& inoutContractState
        );

    void send_message_to_contract(
        const std::string& ContractID,
        const std::string& CreatorID,
        const pc::ContractCode& inContractCode,
        const pc::ContractMessage& inMessage,
        const pdo::state::StateBlockId& inContractStateHash,
        pdo::state::Basic_KV_Plus& inoutContractState,
        bool& outStateChangedFlag,
        std::map<string,string>& outDependencies,
        std::string& outMessageResult
        );

    void Finalize(void);
    void Initialize(void);

    WawakaInterpreter(void);
    ~WawakaInterpreter(void);
};
