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

#pragma once

#include "Response.h"
#include "Value.h"

#include "IssuerAuthority.h"

#define ISSUER_AUTHORITY_CHAIN_SCHEMA "{"                       \
    SCHEMA_KW(asset_type_identifier,"") ","                     \
    SCHEMA_KW(vetting_organization_verifying_key,"") ","        \
    "\"authority_chain\": []"                                   \
    "}"

namespace ww
{
namespace exchange
{

    class IssuerAuthorityChain : public ww::value::Structure
    {
    public:
        bool get_asset_type_identifier(ww::value::String& value) const;
        bool get_vetting_organization_verifying_key(ww::value::String& value) const;
        bool get_authority_chain(ww::value::Array& value) const;
        bool get_dependencies(ww::value::Array& dependencies) const;

        bool set_asset_type_identifier(const ww::value::String& value);
        bool set_vetting_organization_verifying_key(const ww::value::String& value);
        bool set_authority_chain(const ww::value::Array& value);

        bool add_issuer_authority(const ww::exchange::IssuerAuthority& value);

        bool validate(const StringArray& issuer_verifying_key) const;
        bool add_dependencies_to_response(Response& rsp) const;

        IssuerAuthorityChain(void);
        IssuerAuthorityChain(
            const ww::value::String& asset_type_identifier,
            const ww::value::String& vetting_organization_verifying_key);
    };

};
}
