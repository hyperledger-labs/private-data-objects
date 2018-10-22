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

#include "interpreter_kv.h"
#include "state.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

namespace pstate = pdo::state;

class ContractState
{
protected:
    ByteArray ComputeHash(void) const;

public:
    pstate::StateBlockId state_hash_ = {};
    pstate::StateBlockId contract_kv_hash_ = {};
    pstate::Interpreter_KV* kv_;

    ContractState(void){};

    ContractState(const ByteArray& state_encryption_key_,
        const ByteArray& newstate,
        const ByteArray& id_hash,
        const ByteArray& code_hash,
        pstate::Interpreter_KV* kv);

    void Unpack(const ByteArray& state_encryption_key_,
        const JSON_Object* object,
        const ByteArray& id_hash,
        const ByteArray& code_hash);
};
