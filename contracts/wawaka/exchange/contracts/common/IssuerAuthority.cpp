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
#include "IssuerAuthority.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::exchange::IssuerAuthority
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static const ww::exchange::IssuerAuthority issuer_authority_schema;

// -----------------------------------------------------------------
ww::exchange::IssuerAuthority::IssuerAuthority(void) :
    ww::value::Structure(ISSUER_AUTHORITY_SCHEMA)
{
    return;
}

// -----------------------------------------------------------------
ww::exchange::IssuerAuthority::IssuerAuthority(
    const ww::value::String& issuer_verifying_key,
    const ww::exchange::StateReference& reference) :
    ww::value::Structure(ISSUER_AUTHORITY_SCHEMA)
{
    set_authorized_issuer_verifying_key(issuer_verifying_key);
    set_issuer_state_reference(reference);
}

// -----------------------------------------------------------------
SIMPLE_PROPERTY_GET(IssuerAuthority, authorized_issuer_verifying_key, ww::value::String);
SIMPLE_PROPERTY_GET(IssuerAuthority, issuer_state_reference, ww::exchange::StateReference);
SIMPLE_PROPERTY_GET(IssuerAuthority, authorizing_signature, ww::value::String);

SIMPLE_PROPERTY_SET(IssuerAuthority, authorized_issuer_verifying_key, ww::value::String);
SIMPLE_PROPERTY_SET(IssuerAuthority, issuer_state_reference, ww::exchange::StateReference);
SIMPLE_PROPERTY_SET(IssuerAuthority, authorizing_signature, ww::value::String);

// -----------------------------------------------------------------
bool ww::exchange::IssuerAuthority::serialize_for_signing(
    const StringArray& asset_type_identifier,
    StringArray& serialized
    ) const
{
    ww::value::String ati_value((const char*)asset_type_identifier.c_data());

    ww::value::String ivk_value("");
    if (! get_authorized_issuer_verifying_key(ivk_value))
        return false;

    ww::exchange::StateReference isr_value;
    if (! get_issuer_state_reference(isr_value))
        return false;

    // we serialize in an array to ensure that there is a consistent ordering
    ww::value::Array serializer;
    serializer.append_value(ati_value);
    serializer.append_value(ivk_value);
    serializer.append_value(isr_value);

    // serialize the rest of the structure
    if (! serializer.serialize(serialized))
        return false;

    return true;
}

// -----------------------------------------------------------------
bool ww::exchange::IssuerAuthority::sign(
    const StringArray& authorizing_signing_key,
    const StringArray& asset_type_identifier
    )
{
    // serialize the authority for signing
    StringArray serialized;
    if (! serialize_for_signing(asset_type_identifier, serialized))
    {
        CONTRACT_SAFE_LOG(3, "failed to serialize issuer authority");
        return false;
    }

    // sign the serialized authority
    StringArray signature;
    if (! ww::crypto::ecdsa::sign_message(serialized, authorizing_signing_key, signature))
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
    ww::value::String signature_value((const char*)encoded.c_data());
    return set_authorizing_signature(signature_value);
}

// -----------------------------------------------------------------
bool ww::exchange::IssuerAuthority::verify_signature(
    const StringArray& authorizing_verifying_key,
    const StringArray& asset_type_identifier
    ) const
{
    // serialize the authority for signing
    StringArray serialized;
    if (! serialize_for_signing(asset_type_identifier, serialized))
    {
        CONTRACT_SAFE_LOG(3, "failed to serialize issuer authority");
        return false;
    }

    // sign the signature from the object
    const StringArray encoded(get_string("authorizing_signature"));
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
bool ww::exchange::IssuerAuthority::validate(
    const StringArray& authorizing_verifying_key,
    const StringArray& asset_type_identifier
    ) const
{
    if (! validate_schema(issuer_authority_schema))
        return false;

    return verify_signature(authorizing_verifying_key, asset_type_identifier);
}
