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

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class ContractState
{
protected:
    void DecryptState(const ByteArray& state_encryption_key_,
        const ByteArray& encrypted_state,
        const ByteArray& id_hash,
        const ByteArray& code_hash);

    ByteArray EncryptState(const ByteArray& state_encryption_key_,
        const ByteArray& id_hash,
        const ByteArray& code_hash);

    ByteArray ComputeHash(void) const;

public:
    ByteArray encrypted_state_ = {};
    ByteArray decrypted_state_ = {};
    ByteArray state_hash_ = {};

    ContractState(void){};

    ContractState(const ByteArray& state_encryption_key_,
        const ByteArray& newstate,
        const ByteArray& id_hash,
        const ByteArray& code_hash);

    void Unpack(const ByteArray& state_encryption_key_,
        const JSON_Object* object,
        const ByteArray& id_hash,
        const ByteArray& code_hash);
};
