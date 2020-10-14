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

#include "StringArray.h"
#include "Value.h"

#include "Common.h"
#include "StateReference.h"

#define ISSUER_AUTHORITY_SCHEMA "{"                        \
    SCHEMA_KW(authorized_issuer_verifying_key,"") ","           \
    "\"issuer_state_reference\":" STATE_REFERENCE_SCHEMA ","    \
    SCHEMA_KW(authorizing_signature,"")                         \
    "}"

namespace ww
{
namespace exchange
{

    class IssuerAuthority : public ww::value::Structure
    {
    private:
        bool serialize_for_signing(
            const StringArray& asset_type_identifier,
            StringArray& serialized) const;

    public:
        bool get_authorized_issuer_verifying_key(ww::value::String& value) const;
        bool get_issuer_state_reference(ww::exchange::StateReference& value) const;
        bool get_authorizing_signature(ww::value::String& value) const;

        bool set_authorized_issuer_verifying_key(const ww::value::String& value);
        bool set_issuer_state_reference(const ww::exchange::StateReference& value);
        bool set_authorizing_signature(const ww::value::String& value);

        bool sign(
            const StringArray& authorizing_signing_key,
            const StringArray& asset_type_identifier);

        bool verify_signature(
            const StringArray& authorizing_verifying_key,
            const StringArray& asset_type_identifier) const;

        bool validate(
            const StringArray& authorizing_verifying_key,
            const StringArray& asset_type_identifier
            ) const;

        IssuerAuthority(void);

        IssuerAuthority(
            const ww::value::String& issuer_verifying_key,
            const ww::exchange::StateReference& reference);

    };

};
}
