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

#include "LedgerStore.h"
#include "WasmExtensions.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// CLASS: LedgerStore
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ww::exchange::LedgerStore::exists(const StringArray& owner_identity) const
{
    StringArray serialized_entry;
    return get(owner_identity, serialized_entry);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ww::exchange::LedgerStore::get_entry(
    const StringArray& owner_identity,
    ww::exchange::LedgerEntry& value) const
{
    StringArray serialized_entry;
    if (! get(owner_identity, serialized_entry))
        return false;

    if (! serialized_entry.null_terminated())
    {
        CONTRACT_SAFE_LOG(1, "stored ledger entry is not null terminated; %zu", serialized_entry.size());
        return false;
    }

    if (! value.deserialize((const char*)serialized_entry.c_data()))
    {
        CONTRACT_SAFE_LOG(1, "stored ledger entry is not formatted correctly");
        return false;
    }

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ww::exchange::LedgerStore::set_entry(
    const StringArray& owner_identity,
    const ww::exchange::LedgerEntry& value) const
{
    StringArray serialized_entry;
    if (! value.serialize(serialized_entry))
    {
        CONTRACT_SAFE_LOG(1, "ledger entry failed to serialize");
        return false;
    }

    return set(owner_identity, serialized_entry);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ww::exchange::LedgerStore::add_entry(
    const StringArray& owner_identity,
    const StringArray& asset_type_identifier,
    uint32_t count) const
{
    const ww::value::String owner_string((const char*)owner_identity.c_data());
    const ww::value::String asset_type_identifier_string((char*)asset_type_identifier.c_data());

    ww::exchange::Asset asset;

    if (! asset.set_asset_type_identifier(asset_type_identifier_string))
        return false;

    if (! asset.set_count(count))
        return false;

    if (! asset.set_owner_identity(owner_string))
        return false;

    if (! asset.set_escrow_agent_identity(owner_string))
        return false;

    ww::exchange::LedgerEntry entry;

    if (! entry.set_asset(asset))
        return false;

    if (! entry.set_active())
        return false;

    return set_entry(owner_identity, entry);
}
