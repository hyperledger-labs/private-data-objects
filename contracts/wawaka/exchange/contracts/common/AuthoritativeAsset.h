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

#include "Value.h"

#include "Asset.h"
#include "Common.h"
#include "IssuerAuthorityChain.h"
#include "StateReference.h"

#define AUTHORITATIVE_ASSET_SCHEMA "{"                          \
    "\"asset\":" ASSET_SCHEMA ","                               \
    "\"issuer_state_reference\":" STATE_REFERENCE_SCHEMA ","    \
    SCHEMA_KW(issuer_signature,"") ","                          \
    SCHEMA_KW(issuer_identity,"") ","                           \
    "\"issuer_authority_chain\":" ISSUER_AUTHORITY_CHAIN_SCHEMA \
    "}"

namespace ww
{
namespace exchange
{

    class AuthoritativeAsset : public ww::value::Structure
    {
    private:
        bool serialize_for_signing(StringArray& serialized) const;

    public:
        bool get_asset(ww::exchange::Asset& value) const;
        bool get_issuer_state_reference(ww::exchange::StateReference& value) const;
        bool get_issuer_signature(ww::value::String& value) const;
        bool get_issuer_authority_chain(ww::exchange::IssuerAuthorityChain& value) const;

        bool get_issuer_identity(ww::value::String& value) const;

        bool set_asset(const ww::exchange::Asset& value);
        bool set_issuer_state_reference(const ww::exchange::StateReference& value);
        bool set_issuer_signature(const ww::value::String& value);
        bool set_issuer_authority_chain(const ww::exchange::IssuerAuthorityChain& value);

        bool sign(const StringArray& authorizing_signing_key);
        bool verify_signature(const StringArray& authorizing_verifying_key) const;
        bool validate(void) const;

        AuthoritativeAsset(void);
    };

};
}
