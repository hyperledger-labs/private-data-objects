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

#include "crypto.h"
#include "parson.h"

#include "contract_state.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class ContractCode
{
protected:
    ByteArray SerializeForHashing(void) const;
    void ComputeHash(ByteArray& code_hash) const;

public:
    std::string code_;
    std::string name_;
    std::string nonce_;
    ByteArray code_hash_;

    ContractCode(void){};

    void Unpack(const JSON_Object* object);

    void FetchFromState(const ContractState& state, const ByteArray& code_hash);
    void SaveToState(ContractState& state);
};
