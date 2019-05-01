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

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

namespace pstate = pdo::state;

class ContractState
{
public:

    pdo::state::StateBlockId input_block_id_;
    pdo::state::StateBlockId output_block_id_;
    pstate::Interpreter_KV state_;

    ContractState(
        const bool is_initialize,
        const ByteArray& state_encryption_key_,
        const ByteArray& state_hash,
        const ByteArray& id_hash);

    void Finalize(void);

    void Unpack(
        const ByteArray& state_encryption_key_,
        const ByteArray& state_hash,
        const ByteArray& id_hash);

    void Initialize(
        const ByteArray& state_encryption_key_,
        const ByteArray& id_hash);

};
