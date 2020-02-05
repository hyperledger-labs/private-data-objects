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

#include "scheme-private.h"

#include <string>
#include <map>

#include "basic_kv.h"
#include "ContractInterpreter.h"

namespace pc = pdo::contracts;

#define MAX_STATE_SIZE 1<<17

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class GipsyInterpreter : public pc::ContractInterpreter
{
private:
    std::string error_msg_;
    scheme *interpreter_ = NULL;

    const char* report_interpreter_error(
        scheme *sc,
        const char* message,
        const char* error = NULL
        );

    // load functions with throw errors when unsuccessful

    void load_contract_code(
        const pc::ContractCode& inContractCode
        );

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
        std::map<std::string,std::string>& outDependencies,
        std::string& outMessageResult
        );

    void Finalize(void);
    void Initialize(void);

    GipsyInterpreter(void);
    ~GipsyInterpreter(void);
};
