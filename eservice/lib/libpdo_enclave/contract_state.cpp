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

#include "enclave_utils.h"

#include "contract_request.h"
#include "contract_secrets.h"

#include "block_store.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
//
// contract state format
//
// {
//     "EncryptedStateEncryptionKey" : "<base64 encoded encrypted state encryption key>",
//     "ContractID" : "<string>",
//     "CreatorID" : "<string>",
//     "EncryptedState" : ""
// }
//
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractState::ContractState(const ByteArray& state_encryption_key_,
    const ByteArray& newstate,
    const ByteArray& id_hash,
    const ByteArray& code_hash)
    : decrypted_state_(newstate)
{
    EncryptState(state_encryption_key_, id_hash, code_hash);
    state_hash_ = ComputeHash();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractState::DecryptState(const ByteArray& state_encryption_key_,
    const ByteArray& encrypted_state,
    const ByteArray& id_hash,
    const ByteArray& code_hash)
{
    encrypted_state_ = encrypted_state;

    decrypted_state_ = pdo::crypto::skenc::DecryptMessage(state_encryption_key_, encrypted_state_);

    ByteArray decrypted_id_hash(
        decrypted_state_.begin(), decrypted_state_.begin() + SHA256_DIGEST_LENGTH);
    pdo::error::ThrowIf<pdo::error::ValueError>(
        id_hash != decrypted_id_hash,
        "invalid encrypted state; contract id mismatch");

    ByteArray decrypted_code_hash(decrypted_state_.begin() + SHA256_DIGEST_LENGTH,
        decrypted_state_.begin() + (SHA256_DIGEST_LENGTH << 1));
    pdo::error::ThrowIf<pdo::error::ValueError>(
        code_hash != decrypted_code_hash,
        "invalid encrypted state; contract code mismatch");

    decrypted_state_.erase(
        decrypted_state_.begin(), decrypted_state_.begin() + (SHA256_DIGEST_LENGTH << 1));
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray ContractState::EncryptState(
    const ByteArray& state_encryption_key_, const ByteArray& id_hash, const ByteArray& code_hash)
{
    decrypted_state_.insert(decrypted_state_.begin(), code_hash.begin(), code_hash.end());
    decrypted_state_.insert(decrypted_state_.begin(), id_hash.begin(), id_hash.end());
    encrypted_state_ = pdo::crypto::skenc::EncryptMessage(state_encryption_key_, decrypted_state_);

    return encrypted_state_;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray ContractState::ComputeHash(void) const
{
    assert(encrypted_state_.size() > 0);
    return pdo::crypto::ComputeMessageHash(encrypted_state_);
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
            ByteArray decoded_state_hash = base64_decode(pvalue);
            ByteArray encrypted_state;

            pdo_err_t ret = pdo::block_store::BlockStoreGet(decoded_state_hash, encrypted_state);
            pdo::error::ThrowIf<pdo::error::RuntimeError>(
                ret != PDO_SUCCESS, "Failed to retrieve block from the block store");

            DecryptState(state_encryption_key_, encrypted_state, id_hash, code_hash);

            state_hash_ = ComputeHash();
        }
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "unable to unpack contract state");
        throw;
    }
}
