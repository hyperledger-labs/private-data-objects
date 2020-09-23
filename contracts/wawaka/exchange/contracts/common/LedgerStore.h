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

#include <stdint.h>

#include "KeyValue.h"
#include "StringArray.h"

#include "LedgerEntry.h"

namespace ww
{
namespace exchange
{
    class LedgerStore : public KeyValueStore
    {
    public:
        bool add_entry(const StringArray& identity, const StringArray& asset_type_identifier, uint32_t count) const;
        bool get_entry(const StringArray& identity, ww::exchange::LedgerEntry& value) const;
        bool set_entry(const StringArray& identity, const ww::exchange::LedgerEntry& value) const;
        bool exists(const StringArray& identity) const;

        LedgerStore(const char* prefix) : KeyValueStore(prefix) {};
    };

}; // namespace: exchange
} // namespace: ww
