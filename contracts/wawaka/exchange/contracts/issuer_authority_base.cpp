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

#include "Dispatch.h"

#include "KeyValue.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "StringArray.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "exchange_base.h"
#include "issuer_authority_base.h"

#include "common/IssuerAuthority.h"
#include "common/IssuerAuthorityChain.h"
#include "common/StateReference.h"

static KeyValueStore issuer_authority_common_store("issuer_authority_common_store");
static KeyValueStore issuer_authority_approved_keys("issuer_authority_approved_keys");

static const StringArray md_asset_type_id_key("asset_type_identifier");
static const StringArray md_authority_chain_key("authority_chain");

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// CONTRACT METHODS
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
// METHOD: initialize_root_authority
//   initialize key value store for a vetting organization that is
//   the root of trust; that is, there is no associated authority
//   object that needs to be added to the store.
//
// JSON PARAMETERS:
//   asset-type-id -- ecdsa public key for the asset type
//
// RETURNS:
//   true if asset type id successfully saved
// -----------------------------------------------------------------
#define INITIALIZE_ROOT_AUTHORITY_SCHEMA "{\"asset_type_identifier\":\"\"}"
bool ww::exchange::issuer_authority_base::initialize_root_authority(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_UNINITIALIZED(rsp);

    if (! msg.validate_schema(INITIALIZE_ROOT_AUTHORITY_SCHEMA))
        return rsp.error("invalid request, missing required parameters");

    // Build the root authority chain and save it in the metadata
    StringArray verifying_key;
    if (! ww::exchange::exchange_base::get_verifying_key(verifying_key))
        return rsp.error("corrupted state; verifying key not found");

    if (! verifying_key.null_terminated())
        return rsp.error("corrupted state; verifying key is not null terminated");

    ww::value::String verifying_key_string((const char*)verifying_key.c_data());

    // Set the asset type
    const ww::value::String asset_type_identifier_string(msg.get_string("asset_type_identifier"));
    if (asset_type_identifier_string.is_null())
        return rsp.error("missing required parameter; asset_type_identifier");

    const StringArray asset_type_identifier(asset_type_identifier_string.get());
    if (! issuer_authority_common_store.set(md_asset_type_id_key, asset_type_identifier))
        return rsp.error("failed to store the asset type id");

    if (! asset_type_identifier.null_terminated())
        return rsp.error("corrupted request; asset type identifier is not null terminated");

    // Save the serialized authority object
    ww::exchange::IssuerAuthorityChain authority_chain(asset_type_identifier_string, verifying_key_string);

    StringArray serialized_authority_chain;
    if (! authority_chain.serialize(serialized_authority_chain))
        return rsp.error("failed to save authority chain; serialization failed");

    if (! issuer_authority_common_store.set(md_authority_chain_key, serialized_authority_chain))
        return rsp.error("failed to save authority chain; failed to store data");

    // Mark as initialized
    ww::exchange::exchange_base::mark_initialized();

    // ---------- RETURN ----------
    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: initialize_derived_authority
//   initialize the key value store for an issuer that derives authority
//   from another object such as a vetting organization or another issuer
//
// JSON PARAMETERS:
//  asset_authority_chain -- the object that grants issuance
//    authority to this contract
//
// RETURNS:
//   true
// -----------------------------------------------------------------
bool ww::exchange::issuer_authority_base::initialize_derived_authority(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_UNINITIALIZED(rsp);

    // Validate the authority given to the contract object
    ww::exchange::IssuerAuthorityChain authority_chain;
    if (! msg.get_value("asset_authority_chain", authority_chain))
        return rsp.error("missing required parameter; asset_authority_chain");

    StringArray verifying_key;
    if (! ww::exchange::exchange_base::get_verifying_key(verifying_key))
        return rsp.error("corrupted state; verifying key not found");

    if (! authority_chain.validate_issuer_key(verifying_key))
        return rsp.error("invalid parameter; authority chain validation failed");

    // Save the serialized authority chain object
    StringArray serialized_authority_chain;
    if (! authority_chain.serialize(serialized_authority_chain))
        return rsp.error("failed to save authority chain; serialization failed");

    if (! issuer_authority_common_store.set(md_authority_chain_key, serialized_authority_chain))
        return rsp.error("failed to save authority chain; failed to store data");

    // Save the asset type identifier
    const StringArray asset_type_id(authority_chain.get_string("asset_type_identifier"));
    if (! issuer_authority_common_store.set(md_asset_type_id_key, asset_type_id))
        return rsp.error("failed to store the asset type id");

    // Mark as initialized
    ww::exchange::exchange_base::mark_initialized();

    // ---------- RETURN ----------

    // the authority given to the issuer is only valid if all of the
    // dependencies have been committed to the ledger
    if (! authority_chain.add_dependencies_to_response(rsp))
        return rsp.error("failed to add dependencies to the response");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: get_asset_type_identifier
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   asset type id as a string
// -----------------------------------------------------------------
bool ww::exchange::issuer_authority_base::get_asset_type_identifier(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    StringArray asset_type_identifier;
    if (! ww::exchange::issuer_authority_base::get_asset_type_identifier(asset_type_identifier))
        return rsp.error("contract state corrupted, no asset type identifier");

    ww::value::String v((char*)asset_type_identifier.c_data());
    return rsp.value(v, false);
}

// -----------------------------------------------------------------
// METHOD: add_approved_issuer
//
// JSON PARAMETERS:
//   issuer-verifying-key -- verifying key of the asset issuer
//
// RETURNS:
//   true if key is successfully stored
// -----------------------------------------------------------------
bool ww::exchange::issuer_authority_base::add_approved_issuer(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    // Save the issuer's key, would be good to make sure that this is a valid ECDSA key
    StringArray issuer_verifying_key(msg.get_string("issuer_verifying_key"));
    if (! issuer_authority_approved_keys.set(issuer_verifying_key, 1))
        return rsp.error("failed to save the issuer verifying key");

    // ---------- RETURN ----------
    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: get_authority
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   serialized authority object for this contract
// -----------------------------------------------------------------
bool ww::exchange::issuer_authority_base::get_authority(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    ww::exchange::IssuerAuthorityChain authority_chain;
    if (! get_authority(authority_chain))
        return rsp.error("failed to retrieve authority chain");

    return rsp.value(authority_chain, false);
}

// -----------------------------------------------------------------
// METHOD: get_issuer_authority
//
// JSON PARAMETERS:
//   issuer-verifying-key -- verifying key of the asset issuer
//
// RETURNS:
//   serialized authority object
// -----------------------------------------------------------------
bool ww::exchange::issuer_authority_base::get_issuer_authority(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    // Retrieve the issuer's key from the parameter list
    const StringArray issuer_verifying_key(msg.get_string("issuer_verifying_key"));

    uint32_t flag;
    if (! issuer_authority_approved_keys.get(issuer_verifying_key, flag))
        return rsp.error("not an approved authority");

    // Retrieve information from the current state of the contract
    StringArray asset_type_identifier;
    if (! issuer_authority_common_store.get(md_asset_type_id_key, asset_type_identifier))
        return rsp.error("corrupted state; asset type identifier not found");

    StringArray verifying_key;
    if (! ww::exchange::exchange_base::get_verifying_key(verifying_key))
        return rsp.error("corrupted state; verifying key not found");

    StringArray signing_key;
    if (! ww::exchange::exchange_base::get_signing_key(signing_key))
        return rsp.error("corrupted state; signing key not found");

    // --------------- Build the authority chain ---------------
    StringArray serialized_authority_chain;
    if (! issuer_authority_common_store.get(md_authority_chain_key, serialized_authority_chain))
        return rsp.error("corrupted state; serialized authority chain not found");

    ww::exchange::IssuerAuthorityChain authority_chain;
    if (! authority_chain.deserialize((const char*)serialized_authority_chain.c_data()))
        return rsp.error("failed to save authority chain; serialization failed");

    const ww::exchange::StateReference state_reference(env);
    const ww::value::String string_issuer_verifying_key((const char*)issuer_verifying_key.c_data());

    ww::exchange::IssuerAuthority authority(string_issuer_verifying_key, state_reference);
    if (! authority.sign(signing_key, asset_type_identifier))
        return rsp.error("failed to compute signature");

    if (! authority_chain.add_issuer_authority(authority))
        return rsp.error("failed to create issuer authority chain");

    return rsp.value(authority_chain, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// UTILITY FUNCTIONS
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
bool ww::exchange::issuer_authority_base::get_asset_type_identifier(
    StringArray& asset_type_identifier)
{
    if (! issuer_authority_common_store.get(md_asset_type_id_key, asset_type_identifier))
        return false;

    return true;
}

// -----------------------------------------------------------------
bool ww::exchange::issuer_authority_base::get_authority(
    ww::exchange::IssuerAuthorityChain& authority_chain)
{
    // Retrieve the authority chain from state
    StringArray serialized_authority_chain;
    if (! issuer_authority_common_store.get(md_authority_chain_key, serialized_authority_chain))
        return false;

    if (! authority_chain.deserialize((const char*)serialized_authority_chain.c_data()))
        return false;

    return true;
}
