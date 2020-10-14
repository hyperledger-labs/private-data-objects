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

#include "Value.h"

#include "Asset.h"
#include "AuthoritativeAsset.h"
#include "Common.h"
#include "Cryptography.h"
#include "IssuerAuthorityChain.h"
#include "StateReference.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::exchange::AuthoritativeAsset
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
ww::exchange::AuthoritativeAsset::AuthoritativeAsset(void) :
    ww::value::Structure(AUTHORITATIVE_ASSET_SCHEMA)
{
    return;
}

// -----------------------------------------------------------------
bool ww::exchange::AuthoritativeAsset::serialize_for_signing(StringArray& serialized) const
{
    // we do not serialize the authority chain because it is
    // bound to the asset through the verifying key that it
    // establishes. that is, the authority chain establishes
    // the authority of the key that signs the asset and state
    // reference so we do not need to include it in the
    // serialized buffer

    ww::exchange::Asset asset;
    if (! get_asset(asset))
        return false;

    ww::exchange::StateReference state_reference;
    if (! get_issuer_state_reference(state_reference))
        return false;

    // we serialize in an array to ensure that there is a consistent ordering
    ww::value::Array serializer;
    serializer.append_value(asset);
    serializer.append_value(state_reference);

    // serialize the rest of the structure
    if (! serializer.serialize(serialized))
        return false;

    return true;
}

// -----------------------------------------------------------------
bool ww::exchange::AuthoritativeAsset::sign(const StringArray& authorizing_signing_key)
{
    StringArray serialized;
    if (! serialize_for_signing(serialized))
        return false;

    // sign the serialized authority
    StringArray signature;
    if (! ww::crypto::ecdsa::sign_message(serialized, authorizing_signing_key, signature))
    {
        CONTRACT_SAFE_LOG(3, "failed to sign serialized authoritative asset");
        return false;
    }

    // base64 encode the signature so we can use it in the JSON
    StringArray encoded;
    if (! ww::crypto::b64_encode(signature, encoded))
    {
        CONTRACT_SAFE_LOG(3, "failed to encode authoritative asset signature");
        return false;
    }

    // save the encoded array in the signature field
    ww::value::String signature_value((const char*)encoded.c_data());
    return set_issuer_signature(signature_value);
}

// -----------------------------------------------------------------
bool ww::exchange::AuthoritativeAsset::verify_signature(const StringArray& authorizing_verifying_key) const
{
    StringArray serialized;
    if (! serialize_for_signing(serialized))
        return false;

    // sign the signature from the object
    const StringArray encoded(get_string("issuer_signature"));
    StringArray signature;

    if (! ww::crypto::b64_decode(encoded, signature))
    {
        CONTRACT_SAFE_LOG(3, "failed to decode issuer authority signature");
        return false;
    }

    if (! ww::crypto::ecdsa::verify_signature(serialized, authorizing_verifying_key, signature))
    {
        CONTRACT_SAFE_LOG(2, "failed to verify issuer authority");
        return false;
    }

    return true;
}

// -----------------------------------------------------------------
bool ww::exchange::AuthoritativeAsset::validate(void) const
{
    return true;
}

// -----------------------------------------------------------------
SIMPLE_PROPERTY_GET(AuthoritativeAsset, asset, ww::exchange::Asset);
SIMPLE_PROPERTY_GET(AuthoritativeAsset, issuer_state_reference, ww::exchange::StateReference);
SIMPLE_PROPERTY_GET(AuthoritativeAsset, issuer_signature, ww::value::String);
SIMPLE_PROPERTY_GET(AuthoritativeAsset, issuer_authority_chain, ww::exchange::IssuerAuthorityChain)

SIMPLE_PROPERTY_SET(AuthoritativeAsset, asset, ww::exchange::Asset);
SIMPLE_PROPERTY_SET(AuthoritativeAsset, issuer_state_reference, ww::exchange::StateReference);
SIMPLE_PROPERTY_SET(AuthoritativeAsset, issuer_signature, ww::value::String);
SIMPLE_PROPERTY_SET(AuthoritativeAsset, issuer_authority_chain, ww::exchange::IssuerAuthorityChain)
