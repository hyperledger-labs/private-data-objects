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

#include "state.h"
#include "ContractCode.h"
#include "ContractMessage.h"

namespace pdo
{
    namespace contracts
    {
        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        class ContractInterpreter
        {
        public:

            virtual void create_initial_contract_state(
                const std::string& inContractID,
                const std::string& inCreatorID,
                const ContractCode& inContract,
                const ContractMessage& inMessage,
                pdo::state::Basic_KV_Plus& inoutContractState
                ) = 0;

            virtual void send_message_to_contract(
                const std::string& inContractID,
                const std::string& inCreatorID,
                const ContractCode& inContractCode,
                const ContractMessage& inMessage,
                const pdo::state::StateBlockId& inContractStateHash,
                pdo::state::Basic_KV_Plus& inoutContractState,
                bool& outStateChangedFlag,
                std::map<std::string,std::string>& outDependencies,
                std::string& outMessageResult
                ) = 0;

            virtual void Finalize(void) = 0;
            virtual void Initialize(void) = 0;
        };

        extern std::string GetInterpreterIdentity(void);
        extern pdo::contracts::ContractInterpreter* CreateInterpreter(void);
    }

}
