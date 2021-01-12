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

#include "common/AuthoritativeAsset.h"
#include "common/Common.h"
#include "common/Escrow.h"
#include "common/LedgerEntry.h"
#include "common/LedgerStore.h"

static ww::exchange::LedgerStore ledger_store("ledger");

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
    return ww::exchange::exchange_base::initialize_contract(env, rsp);
}

// -----------------------------------------------------------------
// METHOD: initialize
//
// JSON PARAMETERS:
//  asset_authority_chain -- the object that grants issuance
//    authority to this contract
//
// RETURNS:
//   true if asset type id successfully saved
// -----------------------------------------------------------------
bool initialize(const Message& msg, const Environment& env, Response& rsp)
{
    return ww::exchange::issuer_authority_base::initialize_derived_authority(msg, env, rsp);
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
// METHOD: get_asset_type_identifier
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   asset type id as a string
// -----------------------------------------------------------------
bool get_asset_type_identifier(const Message& msg, const Environment& env, Response& rsp)
{
    return ww::exchange::issuer_authority_base::get_asset_type_identifier(msg, env, rsp);
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
bool add_approved_issuer(const Message& msg, const Environment& env, Response& rsp)
{
    return ww::exchange::issuer_authority_base::add_approved_issuer(msg, env, rsp);
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
bool get_issuer_authority(const Message& msg, const Environment& env, Response& rsp)
{
    return ww::exchange::issuer_authority_base::get_issuer_authority(msg, env, rsp);
}

// -----------------------------------------------------------------
// METHOD: get_authority
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   serialized authority object for this issuer
// -----------------------------------------------------------------
bool get_authority(const Message& msg, const Environment& env, Response& rsp)
{
    return ww::exchange::issuer_authority_base::get_authority(msg, env, rsp);
}

// -----------------------------------------------------------------
// METHOD: issue
//
// JSON PARAMETERS:
//   owner_identity
//   count
//
// RETURNS:
//   boolean
// -----------------------------------------------------------------
#define ISSUE_PARAMETER_SCHEMA "{\"owner_identity\":\"\", \"count\":0}"

bool issue(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_INITIALIZED(rsp);

    if (! msg.validate_schema(ISSUE_PARAMETER_SCHEMA))
        return rsp.error("invalid request, missing required parameters");

    // in theory, owner is an escda key, in practice it could be anything
    // but only an ecdsa key can be used meaningfully
    const StringArray owner(msg.get_string("owner_identity"));
    if (owner.size() == 0)
        return rsp.error("invalid request, invalid owner identity parameter");

    if (ledger_store.exists(owner))
        return rsp.error("invalid request, duplicate issuance");

    const int count = (int) msg.get_number("count");
    if (count <= 0)
        return rsp.error("invalid request, invalid asset count");

    StringArray asset_type_identifier;
    if (! ww::exchange::issuer_authority_base::get_asset_type_identifier(asset_type_identifier))
        return rsp.error("contract state corrupted, no asset type identifier");

    if (! ledger_store.add_entry(owner, asset_type_identifier, (uint32_t)count))
        return rsp.error("ledger operation failed, unable to save issuance");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: get_balance
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   current number of assets assigned to the requestor
// -----------------------------------------------------------------
bool get_balance(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    const StringArray owner(env.originator_id_);

    uint32_t balance = 0;

    ww::exchange::LedgerEntry entry;
    if (ledger_store.get_entry(owner, entry))
        balance = entry.get_count();

    ww::value::Number balance_value(balance);
    return rsp.value(balance_value, false);
}

// -----------------------------------------------------------------
// METHOD: get_entry
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   current number of assets assigned to the requestor
// -----------------------------------------------------------------
bool get_entry(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    const StringArray owner(env.originator_id_);

    ww::exchange::LedgerEntry entry;
    ASSERT_SUCCESS(rsp, ledger_store.get_entry(owner, entry), "no entry for originator");

    return rsp.value(entry, false);
}

// -----------------------------------------------------------------
// METHOD: transfer
//
// JSON PARAMETERS:
//   new_owner_identity
//   count
//
// RETURNS:
//   boolean
// -----------------------------------------------------------------
#define TRANSFER_PARAMETER_SCHEMA "{\"new_owner_identity\":\"\", \"count\":0}"

bool transfer(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    if (! msg.validate_schema(TRANSFER_PARAMETER_SCHEMA))
        return rsp.error("invalid request, missing required parameters");

    const int count = (int) msg.get_number("count");
    if (count <= 0)
        return rsp.error("invalid transfer request, invalid asset count");

    const StringArray new_owner(msg.get_string("new_owner_identity"));
    if (new_owner.size() == 0)
        return rsp.error("invalid transfer request, invalid owner identity parameter");

    const StringArray old_owner(env.originator_id_);

    // if there is no issuance for this identity, we treat it as a 0 balance
    ww::exchange::LedgerEntry old_entry;

    if (! ledger_store.get_entry(old_owner, old_entry))
        return rsp.error("transfer failed, insufficient balance for transfer");

    if (old_entry.get_count() < count)
        return rsp.error("transfer failed, insufficient balance for transfer");

    if (! old_entry.is_active())
        return rsp.error("transfer failed, old assets are escrowed");

    // in theory, owner is an escda key, in practice it could be anything
    // but only an ecdsa key can be used meaningfully
    if (! ledger_store.exists(new_owner))
    {
        StringArray asset_type_identifier;
        if (! ww::exchange::issuer_authority_base::get_asset_type_identifier(asset_type_identifier))
            return rsp.error("contract state corrupted, no asset type identifier");

        if (! ledger_store.add_entry(new_owner, asset_type_identifier, 0))
            return rsp.error("transfer failed, failed to add new owner");
    }

    ww::exchange::LedgerEntry new_entry;
    if (! ledger_store.get_entry(new_owner, new_entry))
        return rsp.error("transfer failed, failed to find new owner");

    if (! new_entry.is_active())
        return rsp.error("invalid transfer request, new assets are escrowed");

    // after all the set up, finally transfer the assets
    old_entry.set_count(old_entry.get_count() - (uint32_t)count);
    if (! ledger_store.set_entry(old_owner, old_entry))
        return rsp.error("transfer failed, unable to update old entry");

    new_entry.set_count(new_entry.get_count() + (uint32_t)count);
    if (! ledger_store.set_entry(new_owner, new_entry))
        return rsp.error("transfer failed, unable to update new entry");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: escrow
//
// JSON PARAMETERS:
//   escrow_agent_identity
//
// RETURNS:
//   boolean
// -----------------------------------------------------------------
#define ESCROW_PARAMETER_SCHEMA "{\"escrow_agent_identity\":\"\"}"

bool escrow(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    if (! msg.validate_schema(ESCROW_PARAMETER_SCHEMA))
        return rsp.error("invalid escrow request, missing required parameters");

    const ww::value::String escrow_agent(msg.get_string("escrow_agent_identity"));

    const StringArray owner(env.originator_id_);

    // if there is no issuance for this identity, we treat it as a 0 balance
    ww::exchange::LedgerEntry entry;

    if (! ledger_store.get_entry(owner, entry))
        return rsp.error("escrow failed, no entry for requestor");

    if (! entry.is_active())
        return rsp.error("escrow failed, assets are already escrowed");

    entry.set_inactive(escrow_agent);

    if (! ledger_store.set_entry(owner, entry))
        return rsp.error("escrow failed, unable to update entry");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: escrow_attestation
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   authoritative_asset_type
// -----------------------------------------------------------------
bool escrow_attestation(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    const StringArray owner(env.originator_id_);

    // if there is no issuance for this identity, we treat it as a 0 balance
    ww::exchange::LedgerEntry entry;
    if (! ledger_store.get_entry(owner, entry))
        return rsp.error("invalid escrow attestation request; no entry for requestor");

    if (entry.is_active())
        return rsp.error("invalid escrow attestation request, asset is not in escrow");

    const ww::exchange::StateReference state_reference(env);

    ww::exchange::Asset asset;
    if (! entry.get_asset(asset))
        return rsp.error("corrupted state, invalid asset in ledger");

    ww::exchange::IssuerAuthorityChain authority_chain;
    if (! ww::exchange::issuer_authority_base::get_authority(authority_chain))
        return rsp.error("failed to retrieve issuer authority");

    ww::exchange::AuthoritativeAsset authoritative_asset;

    SAFE_SET(rsp, state_reference, authoritative_asset, issuer_state_reference);
    SAFE_SET(rsp, asset, authoritative_asset, asset);
    SAFE_SET(rsp, authority_chain, authoritative_asset, issuer_authority_chain);

    StringArray signing_key;
    if (! ww::exchange::exchange_base::get_signing_key(signing_key))
        return rsp.error("corrupted state; signing key not found");

    if (! authoritative_asset.sign(signing_key))
        return rsp.error("corrupted state; signature failed");

    return rsp.value(authoritative_asset, false);
}

// -----------------------------------------------------------------
// METHOD: release
//
// JSON PARAMETERS:
//   escrow_agent_state_reference
//   escrow_agent_signature
//
// RETURNS:
//   boolean
// -----------------------------------------------------------------
#define RELEASE_PARAMETER_SCHEMA "{"                     \
    "\"release_request\":" ESCROW_RELEASE_SCHEMA        \
    "}"

bool release(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    // handle the parameters
    ASSERT_SUCCESS(rsp, msg.validate_schema(RELEASE_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    ww::exchange::EscrowRelease release_request;
    ASSERT_SUCCESS(rsp, msg.get_value("release_request", release_request),
                   "invalid request, malformed parameter, release_request");

    // get the ledger entry and make sure it has actually been escrowed
    const StringArray current_owner(env.originator_id_);

    ww::exchange::LedgerEntry ledger_entry;
    ASSERT_SUCCESS(rsp, ledger_store.get_entry(current_owner, ledger_entry),
                   "invalid request, assets are not escrowed");
    ASSERT_SUCCESS(rsp, ! ledger_entry.is_active(),
                   "invalid request, assets are not escrowed");

    // verify the escrow agent signature
    StringArray ledger_escrow_agent_identity;
    SAFE_STRING_ARRAY_GET(rsp, ledger_escrow_agent_identity, ledger_entry, escrow_agent_identity);

    ww::exchange::Asset asset;
    SAFE_GET(rsp, asset, ledger_entry, asset);

    ASSERT_SUCCESS(rsp, release_request.verify_signature(asset, ledger_escrow_agent_identity),
                   "escrow signature verification failed");

    // now modify the entry to mark it as active
    ledger_entry.set_active();
    ASSERT_SUCCESS(rsp, ledger_store.set_entry(current_owner, ledger_entry),
                   "escrow failed, unable to update entry");

    // add the dependency to the response
    ww::exchange::StateReference escrow_agent_state_reference;
    SAFE_GET(rsp, escrow_agent_state_reference, release_request, escrow_agent_state_reference);

    ASSERT_SUCCESS(rsp, escrow_agent_state_reference.add_to_response(rsp),
                   "release request failed, unable to save state reference");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: claim
//
// JSON PARAMETERS:
//   escrow_claim
//
// RETURNS:
//   boolean
// -----------------------------------------------------------------
#define CLAIM_PARAMETER_SCHEMA "{"              \
    "\"claim_request\":" ESCROW_CLAIM_SCHEMA     \
    "}"

bool claim(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);

    // handle the parameters
    ASSERT_SUCCESS(rsp, msg.validate_schema(CLAIM_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    ww::exchange::EscrowClaim claim_request;
    ASSERT_SUCCESS(rsp, msg.get_value("claim_request", claim_request),
                   "invalid request, malformed parameter, claim_request");

    // get the old owner's entry from the ledger
    StringArray old_owner_identity;
    SAFE_STRING_ARRAY_GET(rsp, old_owner_identity, claim_request, old_owner_identity);

    ww::exchange::LedgerEntry old_owner_entry;
    ASSERT_SUCCESS(rsp, ledger_store.get_entry(old_owner_identity, old_owner_entry),
                   "invalid claim request, no such asset");

    // make sure the old entry is actually escrowed
    ASSERT_SUCCESS(rsp, ! old_owner_entry.is_active(),
                   "invalid claim request, state mismatch");

    // check the signature from the escrow agent
    StringArray escrow_agent_identity;
    SAFE_STRING_ARRAY_GET(rsp, escrow_agent_identity, old_owner_entry, escrow_agent_identity);

    ww::exchange::Asset asset;
    SAFE_GET(rsp, asset, old_owner_entry, asset);

    ASSERT_SUCCESS(rsp, claim_request.verify_signature(asset, escrow_agent_identity),
                   "invalid claim request, signature verification failed");

    // get the new owner's entry from the ledger, create an empty
    // entry if one does not already exist
    const StringArray new_owner_identity(env.originator_id_);
    if (! ledger_store.exists(new_owner_identity))
    {
        const int count = 0;

        StringArray asset_type_identifier;
        ASSERT_SUCCESS(rsp, ww::exchange::issuer_authority_base::get_asset_type_identifier(asset_type_identifier),
                       "contract state corrupted, no asset type identifier");
        ASSERT_SUCCESS(rsp, ledger_store.add_entry(new_owner_identity, asset_type_identifier, (uint32_t)count),
                       "ledger operation failed, unable to save issuance");
    }

    ww::exchange::LedgerEntry new_owner_entry;
    ASSERT_SUCCESS(rsp, ledger_store.get_entry(new_owner_identity, new_owner_entry),
                   "contract state corrupted, no issuance located");

    // -----------------------------------------------------------------
    // must add support for the case where the claim comes from
    // an identity that already has an entry in the ledger, we
    // could end up in a case where bi-lateral escrow can be
    // manipulated... if we find an existing entry then we should
    // increment that entry unless it is inactive, for now this
    // prevents some manipulation
    // -----------------------------------------------------------------
    ASSERT_SUCCESS(rsp, new_owner_entry.is_active(), "new owner entry is not active");

    // move the balance from the old owner to the new owner
    uint32_t old_owner_balance = old_owner_entry.get_count();
    uint32_t new_owner_balance = new_owner_entry.get_count();

    old_owner_entry.set_count(0);
    ASSERT_SUCCESS(rsp, ledger_store.set_entry(old_owner_identity, old_owner_entry),
                   "failed to save updated balance");

    new_owner_entry.set_count(old_owner_balance + new_owner_balance);
    ASSERT_SUCCESS(rsp, ledger_store.set_entry(new_owner_identity, new_owner_entry),
                   "failed to save updated balance");

    // add the dependency to the response
    ww::exchange::StateReference escrow_agent_state_reference;
    SAFE_GET(rsp, escrow_agent_state_reference, claim_request, escrow_agent_state_reference);

    ASSERT_SUCCESS(rsp, escrow_agent_state_reference.add_to_response(rsp),
                   "release request failed, unable to save state reference");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// -----------------------------------------------------------------
contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(initialize),
    CONTRACT_METHOD(get_verifying_key),
    CONTRACT_METHOD(get_asset_type_identifier),
    CONTRACT_METHOD(add_approved_issuer),
    CONTRACT_METHOD(get_issuer_authority),
    CONTRACT_METHOD(get_authority),

    CONTRACT_METHOD(issue),
    CONTRACT_METHOD(get_balance),
    CONTRACT_METHOD(get_entry),
    CONTRACT_METHOD(transfer),
    CONTRACT_METHOD(escrow),
    CONTRACT_METHOD(escrow_attestation),
    CONTRACT_METHOD(release),
    CONTRACT_METHOD(claim),
    { NULL, NULL }
};
