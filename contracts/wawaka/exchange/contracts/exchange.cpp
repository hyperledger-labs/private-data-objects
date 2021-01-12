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

#include "common/AssetRequest.h"
#include "common/AuthoritativeAsset.h"
#include "common/Escrow.h"

static KeyValueStore exchange_state("exchange_state");

static const StringArray md_asset_request("asset_request");
static const StringArray md_current_state("current_state");
static const StringArray md_offered_asset("offered_asset");
static const StringArray md_exchanged_asset("exchanged_asset");
static const StringArray md_exchanged_asset_owner("exchanged_asset_owner");

#define EXCHANGE_STATE_START     0
#define EXCHANGE_STATE_OFFERED   1
#define EXCHANGE_STATE_COMPLETED 2
#define EXCHANGE_STATE_CANCELLED 3

#define SET_STATE(rsp, _STATE_)                                         \
do {                                                                    \
    const uint32_t current_state = _STATE_;                             \
    if (! exchange_state.set(md_current_state, current_state))          \
        return rsp.error("failed to initialize contract state");        \
} while (0)

#define CHECK_STATE(rsp, _EXPECTED_STATE_)                              \
do {                                                                    \
    uint32_t current_state;                                             \
    if (! exchange_state.get(md_current_state, current_state))          \
        return rsp.error("unexpected error, failed to retrieve current state"); \
    if (current_state != _EXPECTED_STATE_)                              \
        return rsp.error("operation failed, incorrect state"); \
} while (0)

// -----------------------------------------------------------------
// METHOD: initialize_contract
//   contract initialization method
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   true if successfully initialized
// -----------------------------------------------------------------
bool initialize_contract(const Environment& env, Response& rsp)
{
    SET_STATE(rsp, EXCHANGE_STATE_START);
    return ww::exchange::exchange_base::initialize_contract(env, rsp);
}

// -----------------------------------------------------------------
// METHOD: initialize
//
// JSON PARAMETERS:
//  asset_request
//  authority_verifying_key
//
// RETURNS:
//   true if asset_request is valid
// -----------------------------------------------------------------
#define INITIALIZE_PARAMETER_SCHEMA "{"                                 \
    "\"asset_request\":" ASSET_REQUEST_SCHEMA ","                       \
    "\"offered_authoritative_asset\": " AUTHORITATIVE_ASSET_SCHEMA      \
    "}"
bool initialize(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_UNINITIALIZED(rsp);
    ASSERT_SENDER_IS_OWNER(env, rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(INITIALIZE_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    CHECK_STATE(rsp, EXCHANGE_STATE_START);

    // validate and save the asset request
    ww::exchange::AssetRequest asset_request;
    ASSERT_SUCCESS(rsp, msg.get_value("asset_request", asset_request),
                   "invalid request, malformed parameter, asset_request");

    ww::value::Number count;
    ASSERT_SUCCESS(rsp, asset_request.get_count(count),
                   "invalid request, missing required field, count");
    ASSERT_SUCCESS(rsp, count.get() > 0,
                   "invalid request, count must be a positive number");

    StringArray serialized_asset_request;
    ASSERT_SUCCESS(rsp, asset_request.serialize(serialized_asset_request),
                   "unexpected error, failed to serialize asset request");
    ASSERT_SUCCESS(rsp, exchange_state.set(md_asset_request, serialized_asset_request),
                   "unexpected error, failed to save asset request");

    // validate the offered asset
    ww::exchange::AuthoritativeAsset offered_authoritative_asset;
    ASSERT_SUCCESS(rsp, msg.get_value("offered_authoritative_asset", offered_authoritative_asset),
                   "invalid request, malformed parameter, offered_authoritative_asset");
    ASSERT_SUCCESS(rsp, offered_authoritative_asset.validate(),
                   "invalid request, malformed parameter, offered_authoritative_asset");

    // verify that the asset was escrowed to us
    ww::exchange::Asset asset;
    ASSERT_SUCCESS(rsp, offered_authoritative_asset.get_asset(asset),
                   "invalid request, malformed parameter, asset");
    ww::value::String escrow_agent_identity;
    ASSERT_SUCCESS(rsp, asset.get_escrow_agent_identity(escrow_agent_identity),
                   "invalid request, malformed parameter, escrow_agenty_identity");
    StringArray verifying_key;
    ASSERT_SUCCESS(rsp, ww::exchange::exchange_base::get_verifying_key(verifying_key),
                   "unexpected error, failed to retrieve verifying key");
    ASSERT_SUCCESS(rsp,
                   strncmp(escrow_agent_identity.get(), (const char*)verifying_key.c_data(), verifying_key.size()) == 0,
                   "invalid request, malformed parameter, invalid escrow");

    // serialize and save the offered asset
    StringArray serialized_authoritative_asset;
    ASSERT_SUCCESS(rsp, offered_authoritative_asset.serialize(serialized_authoritative_asset),
                   "unexpected error, failed to serialize authoritative asset");
    ASSERT_SUCCESS(rsp, exchange_state.set(md_offered_asset, serialized_authoritative_asset),
                   "unexpected error, failed to save offered asset");

    // update the state, now ready to accept exchanges
    SET_STATE(rsp, EXCHANGE_STATE_OFFERED);

    // mark the state as initialized and ready
    ww::exchange::exchange_base::mark_initialized();

    // add the asset dependencies to the response
    ww::exchange::IssuerAuthorityChain authority_chain;
    SAFE_GET(rsp, authority_chain, offered_authoritative_asset, issuer_authority_chain);
    ASSERT_SUCCESS(rsp, authority_chain.add_dependencies_to_response(rsp),
                   "unexpected error, failed to add dependencies to response");

    // and return
    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: get_verifying_key
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   ecdsa verifying key
// -----------------------------------------------------------------
bool get_verifying_key(const Message& msg, const Environment& env, Response& rsp)
{
    return ww::exchange::exchange_base::get_verifying_key(msg, env, rsp);
}

// -----------------------------------------------------------------
// METHOD: cancel
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   boolean for success/failure
//
// MODIFIES STATE:
//   true
// -----------------------------------------------------------------
bool cancel(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    ASSERT_SENDER_IS_OWNER(env, rsp);

    CHECK_STATE(rsp, EXCHANGE_STATE_OFFERED);
    SET_STATE(rsp,EXCHANGE_STATE_CANCELLED);

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: cancel_attestation
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   #/pdo/wawaka/exchange/basetypes/escrow_release_type
//
// MODIFIES STATE:
//   false
// -----------------------------------------------------------------
bool cancel_attestation(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    ASSERT_SENDER_IS_OWNER(env, rsp);

    CHECK_STATE(rsp, EXCHANGE_STATE_CANCELLED);

    ww::exchange::EscrowRelease release_request;

    // add the current state reference to the attestation
    const ww::exchange::StateReference state_reference(env);
    ASSERT_SUCCESS(rsp, release_request.set_escrow_agent_state_reference(state_reference),
                   "unexpected error, failed to extract state reference");

    // get the asset for signing
    StringArray serialized_authoritative_asset;
    ASSERT_SUCCESS(rsp, exchange_state.get(md_offered_asset, serialized_authoritative_asset),
                   "unexpected error, failed to get offered asset");

    ww::exchange::AuthoritativeAsset offered_authoritative_asset;
    ASSERT_SUCCESS(rsp, offered_authoritative_asset.deserialize((const char*)serialized_authoritative_asset.c_data()),
                   "unexpected error, failed to deserialized offered asset");

    ww::exchange::Asset asset;
    SAFE_GET(rsp, asset, offered_authoritative_asset, asset);

    // get the signing key
    StringArray signing_key;
    ASSERT_SUCCESS(rsp, ww::exchange::exchange_base::get_signing_key(signing_key),
                   "unexpected error, failed to retrieve signing key");

    // and finally sign the asset and save the signature in the attestation
    ASSERT_SUCCESS(rsp, release_request.sign(asset, signing_key),
                   "unexpected error, failed to sign release attestation");

    return rsp.value(release_request, false);
}

// -----------------------------------------------------------------
// METHOD: examine_offered_asset
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   #/pdo/wawaka/exchange/basetypes/authoritative_asset_type
//
// MODIFIES STATE:
//   false
// -----------------------------------------------------------------
bool examine_offered_asset(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    CHECK_STATE(rsp, EXCHANGE_STATE_OFFERED);

    StringArray serialized_authoritative_asset;
    ASSERT_SUCCESS(rsp, exchange_state.get(md_offered_asset, serialized_authoritative_asset),
                   "unexpected error, failed to get offered asset");

    ww::exchange::AuthoritativeAsset offered_authoritative_asset;
    ASSERT_SUCCESS(rsp, offered_authoritative_asset.deserialize((const char*)serialized_authoritative_asset.c_data()),
                   "unexpected error, failed to deserialized offered asset");

    return rsp.value(offered_authoritative_asset, false);
}

// -----------------------------------------------------------------
// METHOD: examine_requested_asset
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   #/pdo/wawaka/exchange/basetypes/asset_request_type
//
// MODIFIES STATE:
//   false
// -----------------------------------------------------------------
bool examine_requested_asset(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    CHECK_STATE(rsp, EXCHANGE_STATE_OFFERED);

    StringArray serialized_asset_request;
    ASSERT_SUCCESS(rsp, exchange_state.get(md_asset_request, serialized_asset_request),
                   "unexpected error, failed to get requested asset");

    ww::exchange::AssetRequest asset_request;
    ASSERT_SUCCESS(rsp, asset_request.deserialize((const char*)serialized_asset_request.c_data()),
                   "unexpected error, failed to deserialized asset request");

    return rsp.value(asset_request, false);
}

// -----------------------------------------------------------------
// METHOD: exchange_asset
//   submit an asset in response to the asset request
//   the submitted asset must be escrowed to the exchange object
//   the submitted asset must match the request
//
// JSON PARAMETERS:
//   exchanged_authoritative_asset --> #/pdo/wawaka/exchange/basetypes/authoritative_asset_type
//
// RETURNS:
//   boolean
//
// MODIFIES STATE:
//   true
// -----------------------------------------------------------------
#define EXCHANGE_ASSET_SCHEMA "{ \"exchanged_authoritative_asset\": " AUTHORITATIVE_ASSET_SCHEMA " }"
bool exchange_asset(const Message& msg, const Environment& env, Response& rsp)
{
    // if this fails, we should find a way for the exchange to cancel
    // any additional assets that are escrowed to this contract

    ASSERT_INITIALIZED(rsp);
    CHECK_STATE(rsp, EXCHANGE_STATE_OFFERED);

    if (! msg.validate_schema(EXCHANGE_ASSET_SCHEMA))
        return rsp.error("invalid request, missing required parameters");

    // validate the exchange asset
    ww::exchange::AuthoritativeAsset exchanged_authoritative_asset;
    ASSERT_SUCCESS(rsp, msg.get_value("exchanged_authoritative_asset", exchanged_authoritative_asset),
                   "invalid request, malformed parameter, exchanged_authoritative_asset");
    ASSERT_SUCCESS(rsp, exchanged_authoritative_asset.validate(),
                   "invalid request, malformed parameter, exchanged_authoritative_asset");

    // verify that the asset was escrowed to us
    StringArray verifying_key;
    ASSERT_SUCCESS(rsp, ww::exchange::exchange_base::get_verifying_key(verifying_key),
                   "unexpected error, failed to retrieve verifying key");

    ww::exchange::Asset asset;
    SAFE_GET(rsp, asset, exchanged_authoritative_asset, asset);

    ww::value::String escrow_agent_identity;
    SAFE_GET(rsp, escrow_agent_identity, asset, escrow_agent_identity);

    ASSERT_SUCCESS(rsp,
                   strncmp(escrow_agent_identity.get(), (const char*)verifying_key.c_data(), verifying_key.size()) == 0,
                   "invalid request, malformed parameter, invalid escrow");

    // verify the that the message originator is the owner of the asset being offered
    ww::value::String owner_identity;
    SAFE_GET(rsp, owner_identity, asset, owner_identity);
    ASSERT_SUCCESS(rsp, strcmp(owner_identity.get(), env.originator_id_) == 0,
                   "invalid request, only the owner of the asset may offer it in exchange");

    // get the request so we can test the exchanged asset
    StringArray serialized_asset_request;
    ASSERT_SUCCESS(rsp, exchange_state.get(md_asset_request, serialized_asset_request),
                   "unexpected error, failed to get requested asset");

    ww::exchange::AssetRequest asset_request;
    ASSERT_SUCCESS(rsp, asset_request.deserialize((const char*)serialized_asset_request.c_data()),
                   "unexpected error, failed to deserialized asset request");

    ASSERT_SUCCESS(rsp, asset_request.check(exchanged_authoritative_asset),
                   "exchange asset unacceptable");

    // save the exchanged asset and update the state
    StringArray serialized_authoritative_asset;
    ASSERT_SUCCESS(rsp, exchanged_authoritative_asset.serialize(serialized_authoritative_asset),
                   "unexpected error, failed to serialize authoritative asset");
    ASSERT_SUCCESS(rsp, exchange_state.set(md_exchanged_asset, serialized_authoritative_asset),
                   "unexpected error, failed to save exchanged asset");

    const StringArray exchanged_asset_owner(owner_identity.get());
    ASSERT_SUCCESS(rsp, exchange_state.set(md_exchanged_asset_owner, exchanged_asset_owner),
                   "unexpected error, failed to save exchanged asset owner");

    // update the state, now ready to accept exchanges
    SET_STATE(rsp, EXCHANGE_STATE_COMPLETED);

    // add the asset dependencies to the response
    ww::exchange::IssuerAuthorityChain authority_chain;
    SAFE_GET(rsp, authority_chain, exchanged_authoritative_asset, issuer_authority_chain);
    ASSERT_SUCCESS(rsp, authority_chain.add_dependencies_to_response(rsp),
                   "unexpected error, failed to add dependencies to response");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: claim_exchange
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   #/pdo/wawaka/exchange/basetypes/escrow_claim_type
//
// MODIFIES STATE:
//   false
// -----------------------------------------------------------------
bool claim_exchanged_asset(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    ASSERT_SENDER_IS_OWNER(env, rsp);

    CHECK_STATE(rsp, EXCHANGE_STATE_COMPLETED);

    ww::exchange::EscrowClaim claim_request;

    StringArray exchanged_asset_owner;
    ASSERT_SUCCESS(rsp, exchange_state.get(md_exchanged_asset_owner, exchanged_asset_owner),
                   "unexpected error, failed to get exchanged asset owner");
    const ww::value::String exchanged_asset_owner_string((const char*)exchanged_asset_owner.c_data());
    ASSERT_SUCCESS(rsp, claim_request.set_old_owner_identity(exchanged_asset_owner_string),
                   "unexpected error, failed to set exchanged asset owner");

    // add the current state reference to the attestation
    const ww::exchange::StateReference state_reference(env);
    ASSERT_SUCCESS(rsp, claim_request.set_escrow_agent_state_reference(state_reference),
                   "unexpected error, failed to extract state reference");

    // get the asset for signing
    StringArray serialized_authoritative_asset;
    ASSERT_SUCCESS(rsp, exchange_state.get(md_exchanged_asset, serialized_authoritative_asset),
                   "unexpected error, failed to get offered asset");

    ww::exchange::AuthoritativeAsset exchanged_authoritative_asset;
    ASSERT_SUCCESS(rsp, exchanged_authoritative_asset.deserialize((const char*)serialized_authoritative_asset.c_data()),
                   "unexpected error, failed to deserialized exchanged asset");

    ww::exchange::Asset asset;
    SAFE_GET(rsp, asset, exchanged_authoritative_asset, asset);

    // get the signing key
    StringArray signing_key;
    ASSERT_SUCCESS(rsp, ww::exchange::exchange_base::get_signing_key(signing_key),
                   "unexpected error, failed to retrieve signing key");

    // and finally sign the asset and save the signature in the attestation
    ASSERT_SUCCESS(rsp, claim_request.sign(asset, signing_key),
                   "unexpected error, failed to sign claim attestation");

    return rsp.value(claim_request, false);
}

// -----------------------------------------------------------------
// METHOD: claim_offer
//
// JSON PARAMETERS:
//   None
//
// RETURNS:
//   #/pdo/wawaka/exchange/basetypes/escrow_claim_type
//
// MODIFIES STATE:
//   false
// -----------------------------------------------------------------
bool claim_offered_asset(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    CHECK_STATE(rsp, EXCHANGE_STATE_COMPLETED);

    ww::exchange::EscrowClaim claim_request;

    // set the old owner identity
    ASSERT_SUCCESS(rsp, claim_request.set_old_owner_identity(env.creator_id_),
                   "unexpected error, failed to set the old owner identity");

    // add the current state reference to the attestation
    const ww::exchange::StateReference state_reference(env);
    ASSERT_SUCCESS(rsp, claim_request.set_escrow_agent_state_reference(state_reference),
                   "unexpected error, failed to extract state reference");

    // get the asset for signing
    StringArray serialized_authoritative_asset;
    ASSERT_SUCCESS(rsp, exchange_state.get(md_offered_asset, serialized_authoritative_asset),
                   "unexpected error, failed to get offered asset");

    ww::exchange::AuthoritativeAsset offered_authoritative_asset;
    ASSERT_SUCCESS(rsp, offered_authoritative_asset.deserialize((const char*)serialized_authoritative_asset.c_data()),
                   "unexpected error, failed to deserialized offered asset");

    ww::exchange::Asset asset;
    SAFE_GET(rsp, asset, offered_authoritative_asset, asset);

    // get the signing key
    StringArray signing_key;
    ASSERT_SUCCESS(rsp, ww::exchange::exchange_base::get_signing_key(signing_key),
                   "unexpected error, failed to retrieve signing key");

    // and finally sign the asset and save the signature in the attestation
    ASSERT_SUCCESS(rsp, claim_request.sign(asset, signing_key),
                   "unexpected error, failed to sign claim attestation");

    return rsp.value(claim_request, false);
}

// -----------------------------------------------------------------
// -----------------------------------------------------------------
contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(initialize),
    CONTRACT_METHOD(get_verifying_key),
    CONTRACT_METHOD(cancel),
    CONTRACT_METHOD(cancel_attestation),
    CONTRACT_METHOD(examine_offered_asset),
    CONTRACT_METHOD(examine_requested_asset),

    CONTRACT_METHOD(exchange_asset),
    CONTRACT_METHOD(claim_exchanged_asset),
    CONTRACT_METHOD(claim_offered_asset),
    { NULL, NULL }
};
