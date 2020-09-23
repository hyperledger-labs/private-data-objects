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

#include "Common.h"
#include "StateReference.h"

#define ASSET_SCHEMA "{"                   \
    SCHEMA_KW(asset_type_identifier,"") ","     \
    SCHEMA_KW(count,0) ","                      \
    SCHEMA_KW(owner_identity,"") ","            \
    SCHEMA_KW(escrow_agent_identity,"") ","     \
    SCHEMA_KW(escrow_identifier,"")             \
    "}"

namespace ww
{
namespace exchange
{
    class Asset : public ww::value::Structure
    {
    private:
        bool serialize_for_escrow_signing(
            const ww::exchange::StateReference& escrow_agent_state_reference,
            StringArray& serialized) const;

    public:
        bool get_asset_type_identifier(ww::value::String& value) const;
        bool get_count(ww::value::Number& value) const;
        bool get_owner_identity(ww::value::String& value) const;
        bool get_escrow_agent_identity(ww::value::String& value) const;
        bool get_escrow_identifier(ww::value::String& value) const;

        bool set_asset_type_identifier(const ww::value::String& value);
        bool set_count(const ww::value::Number& value);
        bool set_owner_identity(const ww::value::String& value);
        bool set_escrow_agent_identity(const ww::value::String& value);
        bool set_escrow_identifier(const ww::value::String& value);

        bool verify_escrow_signature(
            const ww::exchange::StateReference& escrow_agent_state_reference,
            const StringArray& encoded_signature) const;

        bool sign_for_escrow(
            const ww::exchange::StateReference& escrow_agent_state_reference,
            const StringArray& escrow_agent_signing_key,
            StringArray& encoded_signature) const;

        Asset(void);
    };

};  // namespace exchange
}  // namespace ww
