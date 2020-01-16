/* Copyright 2019 Intel Corporation
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

#include <string>

using namespace std;

#include <unistd.h>
#include <ctype.h>

#include <string>
#include <map>

#include "types.h"

#include "state.h"
#include "ContractCode.h"
#include "ContractMessage.h"

namespace pc = pdo::contracts;
namespace pstate = pdo::state;

namespace pdo
{
    namespace contracts
    {

        void validate_invocation_request(
            const string& request);

        void parse_invocation_response(
            const std::string& response,
            std::string& outResponse,
            bool& outStatus,
            bool& outStateChanged,
            std::map<std::string,std::string>& outDependencies);

        void create_invocation_environment(
            const std::string& ContractID,
            const std::string& CreatorID,
            const pc::ContractCode& inContractCode,
            const pc::ContractMessage& inMessage,
            const pstate::StateBlockId& inContractStateHash,
            std::string& outEnvironment);
    }
}
