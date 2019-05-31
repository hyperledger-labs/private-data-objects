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

#include <cassert>
#include <string>
#include <vector>

#include "error.h"
#include "pdo_error.h"

#include "crypto.h"
#include "hex_string.h"
#include "jsonvalue.h"
#include "packages/base64/base64.h"
#include "parson.h"
#include "types.h"
#include "interpreter_kv.h"

#include "enclave_utils.h"

#include "contract_request.h"
#include "contract_secrets.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
//
// contract KV predefined keys
//
// {
//     "IntrinsicState"     : "<string of scheme state>",
//     "IdHash"             : "<string>",
//     "ContractCode.Code"  : "<string>"
//     "ContractCode.Name"  : "<string>"
//     "ContractCode.Nonce" : "<string>"
//     "ContractCode.Hash"  : "<string>"
// }
//
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractState::ContractState(
    const bool is_initialize,
    const ByteArray& state_encryption_key_,
    const ByteArray& state_hash,
    const ByteArray& id_hash)
    :
    input_block_id_(STATE_BLOCK_ID_LENGTH, 0),
    output_block_id_(STATE_BLOCK_ID_LENGTH, 0),
    state_(is_initialize ?
        /* here the initial state is created */
        pdo::state::Interpreter_KV(state_encryption_key_) :
        /* here the existing state is opened */
        pdo::state::Interpreter_KV(state_hash, state_encryption_key_))
{
    if(is_initialize)
        Initialize(state_encryption_key_, id_hash);
    else // update step
        Unpack(state_encryption_key_, state_hash, id_hash);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractState::Finalize(void)
{
    state_.Finalize(output_block_id_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractState::Unpack(
    const ByteArray& state_encryption_key_,
    const ByteArray& state_hash,
    const ByteArray& id_hash)
{
    const char* pvalue;

    try
    {
        input_block_id_ = state_hash;

        // the contract id stored in state must match the contract id
        // that was given in the request, this ensures that the evaluation
        // occurs on the correct state
        {
            std::string str = "IdHash";
            ByteArray k(str.begin(), str.end());
            pdo::error::ThrowIf<pdo::error::ValueError>(
                id_hash != state_.PrivilegedGet(k), "invalid encrypted state; contract id mismatch");
        }
    }
    catch (std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "%s", e.what());
        // We do not finalize the state. As there has been an error, no output id need be generated.
        throw;
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error, an unknown exception in contract state");
        throw;
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractState::Initialize(
    const ByteArray& state_encryption_key_,
    const ByteArray& id_hash)
{
    try
    {
        SAFE_LOG(PDO_LOG_DEBUG, "Initialize new state");

        // add the contract id into the state so that we can verify
        // that this state belongs to this contract
        {
            std::string str = "IdHash";
            ByteArray k(str.begin(), str.end());
            ByteArray v(id_hash);
            state_.PrivilegedPut(k, v);
        }
    }
    catch (std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "%s", e.what());
        // We do not finalize the state. As there has been an error, no output id need be generated.
        throw;
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error, an unknown exception in contract state");
        throw;
    }
}
