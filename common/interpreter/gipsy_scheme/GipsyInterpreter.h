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

#define MAX_RESULT_SIZE 16000
#define MAX_STATE_SIZE 64000

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class GipsyInterpreter : public pc::ContractInterpreter
{
private:
    std::string error_msg_;
    scheme interpreter_;

    //Convention: we use the key "IntrinsicState" key to store the value
    const std::string intrinsic_state_key_ = "IntrinsicState";

    // load functions with throw errors when unsuccessful

    void load_contract_code(
        const pc::ContractCode& inContractCode
        );

    void load_message(
        const pc::ContractMessage& inMessage
        );

    void load_contract_state(
        const StringArray& inIntrinsicState
        );

    void save_contract_state(
        StringArray& outIntrinsicState
        );

    void save_dependencies(
        std::map<std::string,std::string>& outDependencies
        );
public:

    void create_initial_contract_state(
        const std::string& ContractID,
        const std::string& CreatorID,
        const pc::ContractCode& inContractCode,
        const pc::ContractMessage& inMessage,
        pdo::state::Basic_KV_Plus* inoutContractState
        );

    void send_message_to_contract(
        const std::string& ContractID,
        const std::string& CreatorID,
        const pc::ContractCode& inContractCode,
        const pc::ContractMessage& inMessage,
        const pdo::state::StateBlockId& inContractStateHash,
        pdo::state::Basic_KV_Plus* inoutContractState,
        bool& outStateChangedFlag,
        std::map<string,string>& outDependencies,
        std::string& outMessageResult
        );

    GipsyInterpreter(void);

    ~GipsyInterpreter(void);
};
