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

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractState::ContractState(const ByteArray& state_encryption_key_,
    const ByteArray& newstate,
    const ByteArray& id_hash,
    const ByteArray& code_hash,
    pdo::state::Interpreter_KV* kv)
{
    kv->Uninit(state_hash_);
    contract_kv_hash_ = {};
    SAFE_LOG(PDO_LOG_DEBUG, "state hash: %s", ByteArrayToHexEncodedString(state_hash_).c_str());
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray ContractState::ComputeHash(void) const
{
    //make sure sal has been uninitialized, so to have the latest state hash
    return state_hash_;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractState::Unpack(const ByteArray& state_encryption_key_,
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
            state_hash_ = base64_decode(pvalue);
            kv_ = new pdo::state::Interpreter_KV(state_hash_, state_encryption_key_);
            {
                std::string str = "IdHash";
                ByteArray k(str.begin(), str.end());
                pdo::error::ThrowIf<pdo::error::ValueError>(
                    id_hash != kv_->PrivilegedGet(k), "invalid encrypted state; contract id mismatch");
            }
            {
                std::string str = "CodeHash";
                ByteArray k(str.begin(), str.end());
                pdo::error::ThrowIf<pdo::error::ValueError>(
                    code_hash != kv_->PrivilegedGet(k), "invalid encrypted state; contract code mismatch");
            }
            //leave kv initialized
        }
        else
        {
            SAFE_LOG(PDO_LOG_DEBUG, "No state to unpack");
            /* here the initial state is created */
            ByteArray emptyId;
            kv_ = new pdo::state::Interpreter_KV(emptyId, state_encryption_key_);
            {
                std::string str = "IdHash";
                ByteArray k(str.begin(), str.end());
                ByteArray v(id_hash);
                kv_->PrivilegedPut(k, v);
            }
            {
                std::string str = "CodeHash";
                ByteArray k(str.begin(), str.end());
                ByteArray v(code_hash);
                kv_->PrivilegedPut(k, v);
            }
            state_hash_ = ByteArray(STATE_BLOCK_ID_LENGTH, 0);
            //leave kv initialized
        }
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "unable to unpack contract state");
        kv_->Uninit(state_hash_);
        throw;
    }
}
