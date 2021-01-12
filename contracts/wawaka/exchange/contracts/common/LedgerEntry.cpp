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

#include "LedgerEntry.h"

#include "Cryptography.h"
#include "StringArray.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::exchange::LedgerEntry
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
ww::exchange::LedgerEntry::LedgerEntry(void) :
    ww::value::Structure(LEDGER_ENTRY_SCHEMA)
{}

// -----------------------------------------------------------------
ww::exchange::LedgerEntry::LedgerEntry(const StringArray& serialized) :
    ww::value::Structure(LEDGER_ENTRY_SCHEMA)
{
    if (! serialized.null_terminated())
    {
        CONTRACT_SAFE_LOG(1, "JSON string is not null terminated");
        return;
    }

    deserialize((const char*)serialized.c_data());
}

// -----------------------------------------------------------------
bool ww::exchange::LedgerEntry::is_active(void) const
{
    ww::value::Boolean flag(true);
    if (! get_value("active", flag))
        return false;

    return flag.get();
}

// -----------------------------------------------------------------
bool ww::exchange::LedgerEntry::set_active(void)
{
    const ww::value::String null_string("");
    if (! set_escrow_identifier(null_string))
        return false;

    if (! set_escrow_agent_identity(null_string))
        return false;

    ww::value::Boolean flag(true);
    return set_value("active", flag);
}

// -----------------------------------------------------------------
bool ww::exchange::LedgerEntry::set_inactive(const ww::value::String& escrow_agent_identity)
{
    if (! set_escrow_agent_identity(escrow_agent_identity))
        return false;

    if (! initialize_escrow_identifier())
        return false;

    ww::value::Boolean flag(false);
    return set_value("active", flag);
}

// -----------------------------------------------------------------
uint32_t ww::exchange::LedgerEntry::get_count(void) const
{
    ww::value::Number value;
    if (! get_value("asset.count", value))
        return 0;

    return (uint32_t)value.get();
}

// -----------------------------------------------------------------
bool ww::exchange::LedgerEntry::set_count(uint32_t count)
{
    ww::value::Number value(count);
    return set_value("asset.count", value);
}

// -----------------------------------------------------------------
bool ww::exchange::LedgerEntry::get_owner_identity(ww::value::String& value) const
{
    return get_value("asset.owner_identity", value);
}

bool ww::exchange::LedgerEntry::set_owner_identity(const ww::value::String& value)
{
    return set_value("asset.owner_identity", value);
}

// -----------------------------------------------------------------
bool ww::exchange::LedgerEntry::get_escrow_agent_identity(ww::value::String& value) const
{
    return get_value("asset.escrow_agent_identity", value);
}

bool ww::exchange::LedgerEntry::set_escrow_agent_identity(const ww::value::String& value)
{
    return set_value("asset.escrow_agent_identity", value);
}

// -----------------------------------------------------------------
bool ww::exchange::LedgerEntry::get_escrow_identifier(ww::value::String& value) const
{
    return get_value("asset.escrow_identifier", value);
}

bool ww::exchange::LedgerEntry::set_escrow_identifier(const ww::value::String& value)
{
    return set_value("asset.escrow_identifier", value);
}

// -----------------------------------------------------------------
bool ww::exchange::LedgerEntry::initialize_escrow_identifier(void)
{
    // create a random identifier
    StringArray id_array(32);
    if (! random_identifier(id_array.size(), id_array.data()))
        return false;

    // base64 encode the random identifier
    StringArray encoded;
    if (! ww::crypto::b64_encode(id_array, encoded))
        return false;

    // and save it in the ledger entry
    ww::value::String id_string((const char*)encoded.c_data());
    return set_escrow_identifier(id_string);
}

// -----------------------------------------------------------------
SIMPLE_PROPERTY_GET(LedgerEntry, asset, ww::exchange::Asset);
SIMPLE_PROPERTY_SET(LedgerEntry, asset, ww::exchange::Asset);
