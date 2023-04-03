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
//     "IntrinsicState"     : "<string of contract state>",
//     "IdHash"             : "<ByteArray>",
//     "ContractCode.Code"  : "<string>"
//     "ContractCode.Name"  : "<string>"
//     "ContractCode.Nonce" : "<string>"
//     "ContractCode.CompilationReport" : "<string>"
//     "ContractCode.Hash"  : "<string>"
//     "ContractKeys.Encryption" : "<string>"
//     "ContractKeys.Decryption" : "<string>"
//     "ContractKeys.Signing"    : "<string>"
//     "ContractKeys.Verifying"  : "<string>"
//     "Metadata.Hash" : "<ByteArray>"
// }
//
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractState::ContractState(
    const ByteArray& state_encryption_key,
    const ByteArray& input_block_id,
    const ByteArray& id_hash)
    :
    input_block_id_(STATE_BLOCK_ID_LENGTH, 0),
    output_block_id_(STATE_BLOCK_ID_LENGTH, 0),
    state_(pdo::state::Interpreter_KV(input_block_id, state_encryption_key))
{
    Unpack(state_encryption_key, input_block_id, id_hash);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ContractState::ContractState(
    const ByteArray& state_encryption_key,
    const ByteArray& id_hash)
    :
    input_block_id_(STATE_BLOCK_ID_LENGTH, 0),
    output_block_id_(STATE_BLOCK_ID_LENGTH, 0),
    state_(pdo::state::Interpreter_KV(state_encryption_key))
{
    Initialize(state_encryption_key, id_hash);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractState::Finalize(void)
{
    state_.Finalize(output_block_id_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractState::Unpack(
    const ByteArray& state_encryption_key,
    const ByteArray& input_block_id,
    const ByteArray& id_hash)
{
    const char* pvalue;

    try
    {
        input_block_id_ = input_block_id;

        // the contract id stored in state must match the contract id
        // that was given in the request, this ensures that the evaluation
        // occurs on the correct state
        {
            std::string str = "IdHash";
            ByteArray k(str.begin(), str.end());
            pdo::error::ThrowIf<pdo::error::ValueError>(
                id_hash != state_.PrivilegedGet(k), "invalid encrypted state; contract id mismatch");
        }

        {
            std::string str("Metadata.Hash");
            ByteArray k(str.begin(), str.end());
            metadata_hash_ = state_.PrivilegedGet(k);
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
    const ByteArray& state_encryption_key,
    const ByteArray& id_hash)
{
    try
    {
        SAFE_LOG(PDO_LOG_DEBUG, "Initialize new state");

        ByteArray metadata;

        // add the contract id into the state so that we can verify
        // that this state belongs to this contract
        {
            std::string str = "IdHash";
            ByteArray k(str.begin(), str.end());
            state_.PrivilegedPut(k, id_hash);

            std::copy(id_hash.begin(), id_hash.end(), std::back_inserter(metadata));
        }

        {
            pdo::crypto::sig::PrivateKey privkey;
            privkey.Generate();
            pdo::crypto::sig::PublicKey pubkey(privkey);

            std::string encpriv = privkey.Serialize();
            std::string encpub = pubkey.Serialize();

            {
                std::string str = "ContractKeys.Signing";
                ByteArray k(str.begin(), str.end());
                ByteArray v(encpriv.begin(), encpriv.end());
                state_.PrivilegedPut(k, v);
            }

            {
                std::string str = "ContractKeys.Verifying";
                ByteArray k(str.begin(), str.end());
                ByteArray v(encpub.begin(), encpub.end());
                state_.PrivilegedPut(k, v);
            }

            std::copy(encpub.begin(), encpub.end(), std::back_inserter(metadata));
        }

        {
            pdo::crypto::pkenc::PrivateKey privkey;
            privkey.Generate();
            pdo::crypto::pkenc::PublicKey pubkey(privkey);

            std::string encpriv = privkey.Serialize();
            std::string encpub = pubkey.Serialize();

            {
                std::string str = "ContractKeys.Decryption";
                ByteArray k(str.begin(), str.end());
                ByteArray v(encpriv.begin(), encpriv.end());
                state_.PrivilegedPut(k, v);
            }

            {
                std::string str = "ContractKeys.Encryption";
                ByteArray k(str.begin(), str.end());
                ByteArray v(encpub.begin(), encpub.end());
                state_.PrivilegedPut(k, v);
            }

            std::copy(encpub.begin(), encpub.end(), std::back_inserter(metadata));
        }

        {
            metadata_hash_ = pdo::crypto::ComputeMessageHash(metadata);

            {
                std::string str("Metadata.Hash");
                ByteArray k(str.begin(), str.end());
                state_.PrivilegedPut(k, metadata_hash_);
            }
        }

    }
    catch (std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "%s", e.what());
        throw;
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error, an unknown exception in contract state");
        throw;
    }
}
