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
#include "state.h"

#include "enclave_utils.h"

#include "contract_request.h"
#include "contract_secrets.h"

#include "interpreter_kv.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
//
// contract state format
//
// {
//     "EncryptedStateEncryptionKey" : "<base64 encoded encrypted state encryption key>",
//     "ContractID" : "<string>",
//     "CreatorID" : "<string>",
//     "StateHash" : "<base64 encoded root hash of the state>"
// }
//
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
//
// contract KV predefined keys
//
// {
//     "IntrinsicState" : "<string of scheme state>",
//     "IdHash"         : "<string>",
//     "CodeHash"       : "<string>"
// }
//
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

ContractState::ContractState(void)
{
    input_block_id_.resize(STATE_BLOCK_ID_LENGTH, 0);
    output_block_id_.resize(STATE_BLOCK_ID_LENGTH, 0);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractState::~ContractState(void)
{
    if (state_ != NULL)
        delete state_;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractState::Finalize(void)
{
    pdo::error::ThrowIfNull(state_, "attempt to finalize uninitialized state");
    state_->Finalize(output_block_id_);

    delete state_;
    state_ = NULL;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractState::Unpack(
    const ByteArray& state_encryption_key_,
    const JSON_Object* object,
    const ByteArray& id_hash,
    const ByteArray& code_hash)
{
    const char* pvalue;

    try
    {
        pvalue = json_object_dotget_string(object, "StateHash");
        if (pvalue != NULL && pvalue[0] != '\0')
        {
            input_block_id_ = base64_decode(pvalue);
            state_ = new pdo::state::Interpreter_KV(input_block_id_, state_encryption_key_);

            // verify the integrity of the state, the contract id must match
            // and the code hash must match
            {
                std::string str = "IdHash";
                ByteArray k(str.begin(), str.end());
                pdo::error::ThrowIf<pdo::error::ValueError>(
                    id_hash != state_->PrivilegedGet(k), "invalid encrypted state; contract id mismatch");
            }
            {
                std::string str = "CodeHash";
                ByteArray k(str.begin(), str.end());
                pdo::error::ThrowIf<pdo::error::ValueError>(
                    code_hash != state_->PrivilegedGet(k), "invalid encrypted state; contract code mismatch");
            }
        }
        else
        {
            SAFE_LOG(PDO_LOG_DEBUG, "No state to unpack");
            /* here the initial state is created */
            state_ = new pdo::state::Interpreter_KV(state_encryption_key_);

            // add the contract identity and the code hash into the
            // newly created key value store
            {
                std::string str = "IdHash";
                ByteArray k(str.begin(), str.end());
                ByteArray v(id_hash);
                state_->PrivilegedPut(k, v);
            }
            {
                std::string str = "CodeHash";
                ByteArray k(str.begin(), str.end());
                ByteArray v(code_hash);
                state_->PrivilegedPut(k, v);
            }
        }
    }
    catch (std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "%s", e.what());
        if (state_ != NULL)
        {
            state_->Finalize(input_block_id_);
            state_ = NULL;
        }

        throw;
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "unable to unpack contract state");

        if (state_ != NULL)
        {
            state_->Finalize(input_block_id_);
            state_ = NULL;
        }

        throw;
    }
}
