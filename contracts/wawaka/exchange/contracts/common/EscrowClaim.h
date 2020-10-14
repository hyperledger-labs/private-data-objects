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

#define ESCROW_CLAIM_SCHEMA "{"                                         \
    SCHEMA_KW(old_owner_identity,"") ","                              \
    "\"escrow_agent_state_reference\":" STATE_REFERENCE_SCHEMA ","      \
    SCHEMA_KW(escrow_agent_signature,"")                                \
    "}"

namespace ww
{
namespace exchange
{

    class EscrowClaim : public ww::value::Structure
    {
    private:
        bool serialize_for_signing(
            const ww::value::String& escrow_identifier,
            StringArray& serialized) const;

        bool get_escrow_agent_signature(ww::value::String& value) const;
        bool set_escrow_agent_signature(const ww::value::String& value);

    public:
        bool get_old_owner_identity(ww::value::String& value) const;
        bool get_escrow_agent_state_reference(ww::exchange::StateReference& value) const;

        bool set_old_owner_identity(const ww::value::String& value);
        bool set_escrow_agent_state_reference(const ww::exchange::StateReference& value);

        bool verify_signature(
            const ww::value::String& escrow_identifier,
            const StringArray& escrow_agent_verifying_key) const;

        bool sign(
            const ww::value::String& escrow_identifier,
            const StringArray& escrow_agent_signing_key);

        EscrowClaim(void);
    };

};
}
