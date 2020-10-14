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

#include "WasmExtensions.h"
#include "IssuerAuthorityChain.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::exchange::IssuerAuthorityChain
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

static const ww::exchange::IssuerAuthorityChain issuer_authority_chain_schema;

// -----------------------------------------------------------------
ww::exchange::IssuerAuthorityChain::IssuerAuthorityChain(void) :
    ww::value::Structure(ISSUER_AUTHORITY_CHAIN_SCHEMA)
{
    return;
}

// -----------------------------------------------------------------
ww::exchange::IssuerAuthorityChain::IssuerAuthorityChain(
    const ww::value::String& asset_type_identifier,
    const ww::value::String& vetting_organization_verifying_key) :
    ww::value::Structure(ISSUER_AUTHORITY_CHAIN_SCHEMA)
{
    if (! set_asset_type_identifier(asset_type_identifier))
    {
        CONTRACT_SAFE_LOG(1, "issuer authority chain; failed to set asset type identifier");
        return;
    }

    if (! set_vetting_organization_verifying_key(vetting_organization_verifying_key))
    {
        CONTRACT_SAFE_LOG(1, "issuer authority chain; failed to set verifying key");
        return;
    }

    return;
}

// -----------------------------------------------------------------
SIMPLE_PROPERTY_GET(IssuerAuthorityChain, asset_type_identifier, ww::value::String);
SIMPLE_PROPERTY_GET(IssuerAuthorityChain, vetting_organization_verifying_key, ww::value::String);
SIMPLE_PROPERTY_GET(IssuerAuthorityChain, authority_chain, ww::value::Array);

SIMPLE_PROPERTY_SET(IssuerAuthorityChain, asset_type_identifier, ww::value::String);
SIMPLE_PROPERTY_SET(IssuerAuthorityChain, vetting_organization_verifying_key, ww::value::String);
SIMPLE_PROPERTY_SET(IssuerAuthorityChain, authority_chain, ww::value::Array);

// -----------------------------------------------------------------
bool ww::exchange::IssuerAuthorityChain::add_issuer_authority(const ww::exchange::IssuerAuthority& value)
{
    // there are a lot of copies in here, definitely not the
    // most efficient way to add an authority, but this is safe
    // and is unlikely to be in the middle of a long loop
    ww::value::Array authority_chain;

    if (! get_value("authority_chain", authority_chain))
        return false;

    if (! authority_chain.append_value(value))
        return false;

    if (! set_value("authority_chain", authority_chain))
        return false;

    return true;
}

// -----------------------------------------------------------------
// validate -- verify that the chain establishes the authority of the
// provided issuer verifying key
// -----------------------------------------------------------------
bool ww::exchange::IssuerAuthorityChain::validate(const StringArray& issuer_verifying_key) const
{
    if (! validate_schema(issuer_authority_chain_schema))
        return false;

    ww::value::Array authorities;
    if (! get_authority_chain(authorities))
        return false;

    StringArray type_identifier(get_string("asset_type_identifier"));
    StringArray verifying_key(get_string("vetting_organization_verifying_key"));

    size_t count = authorities.get_count();
    for (size_t index = 0; index < count; index++)
    {
        ww::exchange::IssuerAuthority authority;
        if (! authorities.get_value(index, authority))
            return false;

        if (! authority.validate(verifying_key, type_identifier))
            return false;

        // the key in this authority is used to verify the next authority
        verifying_key.assign(authority.get_string("authorized_issuer_verifying_key"));
    }

    return verifying_key.equal(issuer_verifying_key);
}

// -----------------------------------------------------------------
bool ww::exchange::IssuerAuthorityChain::add_dependencies_to_response(Response& rsp) const
{
    ww::value::Array authorities;
    if (! get_authority_chain(authorities))
        return false;

    size_t count = authorities.get_count();
    for (size_t index = 0; index < count; index++)
    {
        ww::exchange::IssuerAuthority authority;
        if (! authorities.get_value(index, authority))
            return false;

        ww::exchange::StateReference ref;
        if (! authority.get_issuer_state_reference(ref))
            return false;

        if (! rsp.add_dependency(ref.get_string("contract_id"), ref.get_string("state_hash")))
            return false;
    }

    return true;
}
