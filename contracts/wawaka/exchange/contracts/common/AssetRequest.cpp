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

#include "AssetRequest.h"
#include "Common.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::exchange::AssetRequest
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
ww::exchange::AssetRequest::AssetRequest(void) :
    Structure(ASSET_REQUEST_SCHEMA)
{
    return;
}

SIMPLE_PROPERTY_GET(AssetRequest, issuer_verifying_key, ww::value::String);
SIMPLE_PROPERTY_GET(AssetRequest, asset_type_identifier, ww::value::String);
SIMPLE_PROPERTY_GET(AssetRequest, count, ww::value::Number);
SIMPLE_PROPERTY_GET(AssetRequest, owner_identity, ww::value::String);

SIMPLE_PROPERTY_SET(AssetRequest, issuer_verifying_key, ww::value::String);
SIMPLE_PROPERTY_SET(AssetRequest, asset_type_identifier, ww::value::String);
SIMPLE_PROPERTY_SET(AssetRequest, count, ww::value::Number);
SIMPLE_PROPERTY_SET(AssetRequest, owner_identity, ww::value::String);

// -----------------------------------------------------------------
bool ww::exchange::AssetRequest::check(const ww::exchange::AuthoritativeAsset& authoritative_asset) const
{
    // pull the authority chain to look for the issuer key
    ww::exchange::IssuerAuthorityChain authority_chain;
    if (! authoritative_asset.get_issuer_authority_chain(authority_chain))
        return false;

    ww::value::String requested_issuer_verifying_key;
    if (! get_issuer_verifying_key(requested_issuer_verifying_key))
        return false;

    ww::value::String vetting_key;
    if (! authority_chain.get_vetting_organization_verifying_key(vetting_key))
        return false;

    if (strcmp(requested_issuer_verifying_key.get(), vetting_key.get()) != 0)
    {
        // the vetting key isn't what we were looking for, now lets look in
        // the chain for the issuer key
        const StringArray requested_key(requested_issuer_verifying_key.get());
        if (! authority_chain.validate_issuer_key(requested_key))
            return false;
    }

    // get the asset from the authoritative asset
    ww::exchange::Asset asset;
    if (! authoritative_asset.get_asset(asset))
        return false;

    // check the asset type requirement
    ww::value::String requested_asset_type_id, asset_type_id;
    if (! get_asset_type_identifier(requested_asset_type_id))
        return false;
    if (! asset.get_asset_type_identifier(asset_type_id))
        return false;
    if (strcmp(requested_asset_type_id.get(), asset_type_id.get()) != 0)
        return false;

    // check the count requirement
    ww::value::Number requested_count, count;
    if (! get_count(requested_count))
        return false;
    if (! asset.get_count(count))
        return false;
    if (count.get() < requested_count.get())
        return false;

    // check the owner requirement if appropriate
    ww::value::String requested_owner_id, owner_id;
    if (! get_owner_identity(requested_owner_id))
        return false;
    if (! asset.get_owner_identity(owner_id))
        return false;
    if (strlen(requested_owner_id.get()) > 0 && strcmp(requested_owner_id.get(), owner_id.get()) != 0)
        return false;

    return true;
}
