/* Copyright 2019 Intel Corporation
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

#include <stddef.h>
#include <stdint.h>

#include "Types.h"
#include "Dispatch.h"

#include "Attestation.h"
#include "Cryptography.h"
#include "Environment.h"
#include "KeyValue.h"
#include "Message.h"
#include "Response.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "contract/base.h"
#include "contract/attestation.h"

static KeyValueStore contract_attestation_store("meta");
static KeyValueStore contract_endpoint_store("endpoint");

const std::string code_hash_key("code-hash");
const std::string ledger_key("ledger-key");

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: initialize
//
// Method to call during contract initialization to incorporate
// the methods necessary for the attestation functions.
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ww::contract::attestation::initialize_contract(const Environment& env)
{
    if (! set_ledger_key(""))
    {
        CONTRACT_SAFE_LOG(3, "failed to initialize the meta store");
        return false;
    }

    ww::types::ByteArray code_hash;
    if (! set_code_hash(code_hash))
    {
        CONTRACT_SAFE_LOG(3, "failed to initialize the meta store");
        return false;
    }

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: set_ledger_key
//
// Contract method to set the ledger key that will serve as the root
// of trust for verifying contract object attestations.
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ww::contract::attestation::set_ledger_key(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    ASSERT_SENDER_IS_CREATOR(env, rsp);
    ASSERT_SUCCESS(rsp, msg.validate_schema(SET_LEDGER_KEY_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string ledger_verifying_key(msg.get_string("ledger_verifying_key"));
    if (! set_ledger_key(ledger_verifying_key))
        return rsp.error("failed to save the ledger verifying key");

    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: get_ledger_key
//
// Contract method to get the ledger key that has been set as the
// contract object root of trust. Note that this is available to
// anyone. Could be wrapped with additional policy checks.
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ww::contract::attestation::get_ledger_key(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    std::string ledger_verifying_key;
    if (! get_ledger_key(ledger_verifying_key))
        return rsp.error("failed to get the ledger verifying key");

    ww::value::String result(ledger_verifying_key.c_str());
    return rsp.value(result, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: get_contract_metadata
//
// Contract method to get encryption and verifying key associated
// with the contract. Anyone can retrieve this information, it is
// always available in the ledger.
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ww::contract::attestation::get_contract_metadata(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    std::string verifying_key;
    if (! KeyValueStore::privileged_get("ContractKeys.Verifying", verifying_key))
        return rsp.error("failed to retreive privileged value for ContractKeys.Verifying");

    std::string encryption_key;
    if (! KeyValueStore::privileged_get("ContractKeys.Encryption", encryption_key))
        return rsp.error("failed to retreive privileged value for ContractKeys.Encryption");

    ww::value::Structure result(CONTRACT_METADATA_SCHEMA);
    result.set_string("verifying_key", verifying_key.c_str());
    result.set_string("encryption_key", encryption_key.c_str());

    return rsp.value(result, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: get_contract_code_metadata
//
// Contract method to get the code metadata associated with the
// contract. Note that only the creator can get this information.
// It may expose information about the details of the contract that
// should not be public.
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ww::contract::attestation::get_contract_code_metadata(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    ASSERT_SENDER_IS_CREATOR(env, rsp);

    // returning all the information for now though only the nonce
    // should be necessary for the attestation test
    std::string code_nonce;
    ASSERT_SUCCESS(rsp, KeyValueStore::privileged_get("ContractCode.Nonce", code_nonce),
                   "unexpected error: failed to retreive code nonce");

    ww::types::ByteArray code_hash;
    ASSERT_SUCCESS(rsp, ww::contract::attestation::compute_code_hash(code_hash),
                   "unexpected error: failed to retrieve code hash");
    std::string encoded_code_hash;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_encode(code_hash, encoded_code_hash),
                   "unexpected error: failed to encode code hash");

    ww::value::Structure result(CONTRACT_CODE_METADATA_SCHEMA);
    result.set_string("code_nonce", code_nonce.c_str());
    result.set_string("code_hash", encoded_code_hash.c_str());
    return rsp.value(result, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: add_endpoint
//
// Contract method to verify the attestation of a contract object
// and add it to the set of "trusted endpoints". Note that this
// implementation of the method is open to all. It can be wrapped
// with additional policy checks when included in the contract.
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ww::contract::attestation::add_endpoint(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    // to add an endpoint we do need the ledger key
    std::string ledger_key;
    if (! get_ledger_key(ledger_key) && ledger_key.length() > 0)
        return rsp.error("contract has not been initialized");

    // extract the parameters
    ASSERT_SUCCESS(rsp, msg.validate_schema(ADD_ENDPOINT_PARAM_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string contract_id(msg.get_string("contract_id"));
    const std::string ledger_code_hash(msg.get_string("ledger_attestation.contract_code_hash"));
    const std::string ledger_meta_hash(msg.get_string("ledger_attestation.metadata_hash"));
    const std::string ledger_signature(msg.get_string("ledger_attestation.signature"));
    const std::string verifying_key(msg.get_string("contract_metadata.verifying_key"));
    const std::string encryption_key(msg.get_string("contract_metadata.encryption_key"));
    const std::string code_nonce(msg.get_string("contract_code_metadata.code_nonce"));

    // we are going to assume that the invoker of this method is the creator
    // of the contract being added so the creator id will come from the environment
    const std::string creator(env.originator_id_);

    // verify the ledger's signature on the metadata_hash and code_hash
    {
        ww::types::ByteArray buffer;
        std::copy(contract_id.begin(), contract_id.end(), std::back_inserter(buffer));
        std::copy(creator.begin(), creator.end(), std::back_inserter(buffer));
        std::copy(ledger_code_hash.begin(), ledger_code_hash.end(), std::back_inserter(buffer));
        std::copy(ledger_meta_hash.begin(), ledger_meta_hash.end(), std::back_inserter(buffer));

        ww::types::ByteArray signature;
        if (! ww::crypto::b64_decode(ledger_signature, signature))
            return rsp.error("failed to decode ledger signature");
        if (! ww::crypto::ecdsa::verify_signature(buffer, ledger_key, signature))
            return rsp.error("failed to verify ledger signature");
    }

    // verify that the code hash matches the code hash in the ledger
    {
        // we compute the merkle root using the hash of our own code
        // so we know the hash of the other if it matches
        ww::types::ByteArray decoded_code_hash;
        if (! get_code_hash(decoded_code_hash))
            return rsp.error("failed to retrieve code hash");

        ww::types::ByteArray nonce(code_nonce.begin(), code_nonce.end());
        ww::types::ByteArray decoded_nonce_hash;
        if (! ww::crypto::crypto_hash(nonce, decoded_nonce_hash))
            return rsp.error("failed to hash code nonce");

        ww::types::ByteArray buffer;
        std::copy(decoded_code_hash.begin(), decoded_code_hash.end(), std::back_inserter(buffer));
        std::copy(decoded_nonce_hash.begin(), decoded_nonce_hash.end(), std::back_inserter(buffer));

        ww::types::ByteArray decoded_code_hash_root;
        if (! ww::crypto::crypto_hash(buffer, decoded_code_hash_root))
            return rsp.error("failed to create the code hash root");

        ww::types::ByteArray decoded_ledger_code_hash;
        if (! ww::crypto::b64_decode(ledger_code_hash, decoded_ledger_code_hash))
            return rsp.error("failed to decoded ledger code hash");

        if (decoded_ledger_code_hash != decoded_code_hash_root)
            return rsp.error("attestation of code hash failed");
    }

    // verify that the metadata hash matches the metadata hash in the ledger
    {
        ww::types::ByteArray idhash;
        if (! ww::crypto::b64_decode(contract_id, idhash))
            return rsp.error("failed to decode the contract id");

        ww::types::ByteArray buffer;
        std::copy(idhash.begin(), idhash.end(), std::back_inserter(buffer));
        std::copy(verifying_key.begin(), verifying_key.end(), std::back_inserter(buffer));
        std::copy(encryption_key.begin(), encryption_key.end(), std::back_inserter(buffer));

        ww::types::ByteArray computed_hash;
        if (! ww::crypto::crypto_hash(buffer, computed_hash))
            return rsp.error("failed to compute the hash for metadata comparison");

        ww::types::ByteArray decoded_ledger_meta_hash;
        if (! ww::crypto::b64_decode(ledger_meta_hash, decoded_ledger_meta_hash))
            return rsp.error("failed to decoded ledger code hash");

        if (computed_hash != decoded_ledger_meta_hash)
            return rsp.error("computed metadata hash not the same as the stored hash");
    }

    // now store the information about the endpoint
    if (! add_endpoint(contract_id, verifying_key, encryption_key))
        return rsp.error("unexpected error, failed to store endpoint information");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// Some functions for managing the ledger key
// -----------------------------------------------------------------
bool ww::contract::attestation::set_ledger_key(const std::string& ledger_verifying_key)
{
    return contract_attestation_store.set(ledger_key, ledger_verifying_key);
}

bool ww::contract::attestation::get_ledger_key(std::string& ledger_verifying_key)
{
    return contract_attestation_store.get(ledger_key, ledger_verifying_key);
}

// -----------------------------------------------------------------
// Some functions for managing the code hash
// -----------------------------------------------------------------
bool ww::contract::attestation::set_code_hash(const ww::types::ByteArray& code_hash)
{
    return contract_attestation_store.set(code_hash_key, code_hash);
}

bool ww::contract::attestation::get_code_hash(ww::types::ByteArray& code_hash)
{
    return contract_attestation_store.get(code_hash_key, code_hash);
}

bool ww::contract::attestation::compute_code_hash(ww::types::ByteArray& code_hash)
{
    ww::types::ByteArray code_buffer;
    if (! KeyValueStore::privileged_get("ContractCode.Code", code_buffer))
        return false;

    ww::types::ByteArray name;
    if (! KeyValueStore::privileged_get("ContractCode.Name", name))
        return false;

    std::copy(name.begin(), name.end(), std::back_inserter(code_buffer));

    if (! ww::crypto::crypto_hash(code_buffer, code_hash))
        return false;

    return true;
}

// -----------------------------------------------------------------
// Some functions for managing the endpoint registry
// -----------------------------------------------------------------
static const std::string ep_verifying_key("verifying_key");
static const std::string ep_encryption_key("encryption_key");

bool ww::contract::attestation::add_endpoint(
    const std::string& contract_id,
    const std::string& verifying_key,
    const std::string& encryption_key)
{
    // now store the information about the endpoint
    ww::value::Object endpoint_information;
    endpoint_information.set_string("verifying_key", verifying_key.c_str());
    endpoint_information.set_string("encryption_key", encryption_key.c_str());

    std::string serialized_endpoint_information;
    if (! endpoint_information.serialize(serialized_endpoint_information))
    {
        CONTRACT_SAFE_LOG(3, "failed to serialize endpoint information");
        return false;
    }

    if (! contract_endpoint_store.set(contract_id, serialized_endpoint_information))
    {
        CONTRACT_SAFE_LOG(3, "failed to save the endpoint information");
        return false;
    }

    return true;
}

bool ww::contract::attestation::get_endpoint(
    const std::string& contract_id,
    std::string& verifying_key,
    std::string& encryption_key)
{
    std::string serialized_endpoint_information;
    if (! contract_endpoint_store.get(contract_id, serialized_endpoint_information))
    {
        CONTRACT_SAFE_LOG(1, "endpoint not registered");
        return false;
    }

    ww::value::Object endpoint_information;
    if (! endpoint_information.deserialize(serialized_endpoint_information.c_str()))
    {
        CONTRACT_SAFE_LOG(3, "unexpected error, failed to deserialize endpoint information");
        return false;
    }

    verifying_key = endpoint_information.get_string(ep_verifying_key.c_str());
    encryption_key = endpoint_information.get_string(ep_encryption_key.c_str());
    return true;
}
