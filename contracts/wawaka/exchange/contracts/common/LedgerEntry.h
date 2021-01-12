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

#define LEDGER_ENTRY_SCHEMA "{"                 \
    SCHEMA_KW(active, true) ","                 \
    "\"asset\":" ASSET_SCHEMA                   \
    "}"

namespace ww
{
namespace exchange
{

    class LedgerEntry : public ww::value::Structure
    {
    protected:
        bool initialize_escrow_identifier(void);

        bool get_escrow_identifier(ww::value::String& value) const;
        bool set_escrow_identifier(const ww::value::String& value);

    public:
        bool is_active(void) const;
        bool set_active();
        bool set_inactive(const ww::value::String& escrow_agent_identity);

        bool get_asset(ww::exchange::Asset& value) const;
        bool set_asset(const ww::exchange::Asset& value);

        uint32_t get_count(void) const;
        bool set_count(const uint32_t count);

        bool get_owner_identity(ww::value::String& value) const;
        bool set_owner_identity(const ww::value::String& value);

        bool get_escrow_agent_identity(ww::value::String& value) const;
        bool set_escrow_agent_identity(const ww::value::String& value);

        LedgerEntry(const StringArray& serialized);
        LedgerEntry(void);
    };

};
}
