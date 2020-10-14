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

#include "Asset.h"
#include "Cryptography.h"
#include "StateReference.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::exchange::Asset
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
ww::exchange::Asset::Asset(void) :
    ww::value::Structure(ASSET_SCHEMA)
{
    return;
}

// -----------------------------------------------------------------
SIMPLE_PROPERTY_GET(Asset, asset_type_identifier, ww::value::String);
SIMPLE_PROPERTY_GET(Asset, count, ww::value::Number);
SIMPLE_PROPERTY_GET(Asset, owner_identity, ww::value::String);
SIMPLE_PROPERTY_GET(Asset, escrow_agent_identity, ww::value::String);
SIMPLE_PROPERTY_GET(Asset, escrow_identifier, ww::value::String);

SIMPLE_PROPERTY_SET(Asset, asset_type_identifier, ww::value::String);
SIMPLE_PROPERTY_SET(Asset, count, ww::value::Number);
SIMPLE_PROPERTY_SET(Asset, owner_identity, ww::value::String);
SIMPLE_PROPERTY_SET(Asset, escrow_agent_identity, ww::value::String);
SIMPLE_PROPERTY_SET(Asset, escrow_identifier, ww::value::String);

// -----------------------------------------------------------------
bool ww::exchange::Asset::serialize_for_escrow_signing(
    const ww::exchange::StateReference& escrow_agent_state_reference,
    StringArray& serialized) const
{
    ww::value::Array serializer;
    serializer.append_value(*this);
    serializer.append_value(escrow_agent_state_reference);

    if (! serializer.serialize(serialized))
        return false;

    return true;
}

// -----------------------------------------------------------------
bool ww::exchange::Asset::sign_for_escrow(
    const ww::exchange::StateReference& escrow_agent_state_reference,
    const StringArray& escrow_agent_signing_key,
    StringArray& encoded_signature) const
{
    // serialize the asset
    StringArray serialized;
    if (! serialize_for_escrow_signing(escrow_agent_state_reference, serialized))
        return false;

    // sign the serialized authority
    StringArray signature;
    if (! ww::crypto::ecdsa::sign_message(serialized, escrow_agent_signing_key, signature))
    {
        CONTRACT_SAFE_LOG(3, "failed to sign serialized authoritative asset");
        return false;
    }

    // base64 encode the signature so we can use it in the JSON
    if (! ww::crypto::b64_encode(signature, encoded_signature))
    {
        CONTRACT_SAFE_LOG(3, "failed to encode authoritative asset signature");
        return false;
    }

    return true;
}

// -----------------------------------------------------------------
bool ww::exchange::Asset::verify_escrow_signature(
    const ww::exchange::StateReference& escrow_agent_state_reference,
    const StringArray& encoded_signature) const
{
    // get the escrow agent verifying key
    ww::value::String escrow_agent_identity_string;
    if (! get_escrow_agent_identity(escrow_agent_identity_string))
        return false;

    const StringArray escrow_agent_verifying_key(escrow_agent_identity_string.get());

    // serialize the asset
    StringArray serialized;
    if (! serialize_for_escrow_signing(escrow_agent_state_reference, serialized))
        return false;

    // sign the signature from the object
    StringArray signature;

    if (! ww::crypto::b64_decode(encoded_signature, signature))
    {
        CONTRACT_SAFE_LOG(3, "failed to decode issuer authority signature");
        return false;
    }

    if (! ww::crypto::ecdsa::verify_signature(serialized, escrow_agent_verifying_key, signature))
    {
        CONTRACT_SAFE_LOG(2, "failed to verify issuer authority");
        return false;
    }

    return true;
}
