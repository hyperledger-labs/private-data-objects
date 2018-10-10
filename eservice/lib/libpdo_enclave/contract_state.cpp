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

#include "enclave_t.h"

#include "wrapper_ocall_BlockStore.h"
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
    const ByteArray& code_hash)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !g_sal.initialized(), "SAL not initialized before uninit");
    //uninitialize State Abstraction Layer and get the id
    state_status_t ret;
    ret = g_sal.uninit(&state_hash_);
    pdo::error::ThrowIf<pdo::error::ValueError>(
        ret != STATE_SUCCESS, "sal uninit error");
    contract_kv_hash_ = {};
    SAFE_LOG(PDO_LOG_DEBUG, "state hash: %s\n", ByteArrayToHexEncodedString(state_hash_).c_str());
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray ContractState::ComputeHash(void) const
{
    //make sure sal has been uninitialized, so to have the latest state hash
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        g_sal.initialized(), "SAL still initialized before taking hash, SAL uninit needed");
    return state_hash_;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractState::Unpack(const ByteArray& state_encryption_key_,
    const JSON_Object* object,
    const ByteArray& id_hash,
    const ByteArray& code_hash)
{
    const char* pvalue;

    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        g_sal.initialized(), "SAL already initialized before state unpacking");

    try
    {
        pvalue = json_object_dotget_string(object, "StateHash");
        if (pvalue != NULL && pvalue[0] != '\0')
        {
            state_hash_ = base64_decode(pvalue);

            {//initialize SAL from state root hash
                pdo::error::ThrowIf<pdo::error::RuntimeError>(
                    state_hash_.size() == 0, "state hash is empty");
                sebio_set({state_encryption_key_, SEBIO_AES_GCM, NULL, NULL});

                g_sal.init(state_hash_);
                pstate::StateBlockIdRefArray list = g_sal.list();
                //expect 1 item, (i) the contract kv data
                pdo::error::ThrowIf<pdo::error::RuntimeError>(
                    list.size() != 1, "sal has not 1 item");
                contract_kv_hash_ = *list[0];
                //check values in kv
                pstate::Interpreter_KV contract_kv(contract_kv_hash_);
                {
                    std::string str = "IdHash";
                    ByteArray k(str.begin(), str.end());
                    pdo::error::ThrowIf<pdo::error::ValueError>(
                        id_hash != contract_kv.Get(k), "invalid encrypted state; contract id mismatch");
                }
                {
                    std::string str = "CodeHash";
                    ByteArray k(str.begin(), str.end());
                    pdo::error::ThrowIf<pdo::error::ValueError>(
                        code_hash != contract_kv.Get(k), "invalid encrypted state; contract code mismatch");
                }
                contract_kv.Uninit(contract_kv_hash_);
             }
             //keep SAL open
        }
        else
        {
            SAFE_LOG(PDO_LOG_DEBUG, "No state to unpack\n");
            /* here the initial state is created */
            //initialize sebio
            sebio_set({state_encryption_key_, SEBIO_AES_GCM});
            ByteArray emptyId;
            g_sal.init(emptyId);

            {//create empty kv store data for contract interpreter
                void *h;
                state_status_t ret;
                pstate::Interpreter_KV interpreter_kv(emptyId);
                //WARNING: need to put at least one byte, otherwise encryption fails
                {
                    std::string str = "IdHash";
                    ByteArray k(str.begin(), str.end());
                    ByteArray v(id_hash);
                    interpreter_kv.Put(k, v);
                }
                {
                    std::string str = "CodeHash";
                    ByteArray k(str.begin(), str.end());
                    ByteArray v(code_hash);
                    interpreter_kv.Put(k, v);
                }
                interpreter_kv.Uninit(contract_kv_hash_);
                //keep SAL open
            }
        }
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "unable to unpack contract state");
        g_sal.uninit(&state_hash_);
        throw;
    }
}
