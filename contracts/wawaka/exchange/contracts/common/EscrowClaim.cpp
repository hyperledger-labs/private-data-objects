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

#include "Cryptography.h"
#include "Value.h"

#include "EscrowClaim.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::exchange::EscrowClaim
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
ww::exchange::EscrowClaim::EscrowClaim(void) :
    ww::value::Structure(ESCROW_CLAIM_SCHEMA)
{
    return;
}

// -----------------------------------------------------------------
SIMPLE_PROPERTY_GET(EscrowClaim, old_owner_identity, ww::value::String);
SIMPLE_PROPERTY_GET(EscrowClaim, escrow_agent_state_reference, ww::exchange::StateReference);
SIMPLE_PROPERTY_GET(EscrowClaim, escrow_agent_signature, ww::value::String);

SIMPLE_PROPERTY_SET(EscrowClaim, old_owner_identity, ww::value::String);
SIMPLE_PROPERTY_SET(EscrowClaim, escrow_agent_state_reference, ww::exchange::StateReference);
SIMPLE_PROPERTY_SET(EscrowClaim, escrow_agent_signature, ww::value::String);

// -----------------------------------------------------------------
bool ww::exchange::EscrowClaim::serialize_for_signing(
    const ww::value::String& escrow_identifier,
    StringArray& serialized) const
{
    ww::value::String old_owner_identity;
    if (! get_old_owner_identity(old_owner_identity))
        return false;

    ww::exchange::StateReference state_reference;
    if (! get_escrow_agent_state_reference(state_reference))
        return false;

    // we use the array to ensure that the ordering of fields
    // is consistent
    ww::value::Array serializer;
    serializer.append_value(escrow_identifier);
    serializer.append_value(old_owner_identity);
    serializer.append_value(state_reference);

    if (! serializer.serialize(serialized))
        return false;

    return true;
}

// -----------------------------------------------------------------
bool ww::exchange::EscrowClaim::sign(
    const ww::value::String& escrow_identifier,
    const StringArray& escrow_agent_signing_key)
{
    StringArray serialized;
    if (! serialize_for_signing(escrow_identifier, serialized))
        return false;

    // sign the serialized claim
    StringArray signature;
    if (! ww::crypto::ecdsa::sign_message(serialized, escrow_agent_signing_key, signature))
    {
        CONTRACT_SAFE_LOG(3, "failed to sign serialized issuer authority");
        return false;
    }

    // base64 encode the signature so we can use it in the JSON
    StringArray encoded;
    if (! ww::crypto::b64_encode(signature, encoded))
    {
        CONTRACT_SAFE_LOG(3, "failed to encode issuer authority signature");
        return false;
    }

    // save the encoded array in the signature field
    ww::value::String signature_string((const char*)encoded.c_data());
    return set_escrow_agent_signature(signature_string);
}

// -----------------------------------------------------------------
bool ww::exchange::EscrowClaim::verify_signature(
    const ww::value::String& escrow_identifier,
    const StringArray& escrow_agent_verifying_key) const
{
    StringArray serialized;
    if (! serialize_for_signing(escrow_identifier, serialized))
        return false;

    // sign the signature from the object
    ww::value::String signature_string;
    if (! get_escrow_agent_signature(signature_string))
        return false;

    const StringArray encoded(signature_string.get());
    StringArray signature;

    if (! ww::crypto::b64_decode(encoded, signature))
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
