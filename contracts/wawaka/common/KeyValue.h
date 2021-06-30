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

// pick up types from pdo common
#include "Types.h"

class KeyValueStore
{
    size_t handle_;
    const ww::types::ByteArray prefix_;
    bool make_key(const ww::types::ByteArray& key, ww::types::ByteArray& prefixed_key) const;

public:
    KeyValueStore(const std::string& prefix, size_t handle = 0)
        : handle_(handle), prefix_(prefix.begin(), prefix.end()) {};

    static int create(const ww::types::ByteArray& key);
    static int open(const ww::types::ByteArray& block_hash, const ww::types::ByteArray& key);
    static bool finalize(const int kv_store_handle, ww::types::ByteArray& block_hash);

    bool get(const ww::types::ByteArray& key, uint32_t& val) const;
    bool get(const std::string& key, uint32_t& val) const
    {
        ww::types::ByteArray bkey(key.begin(), key.end());
        return get(bkey, val);
    };

    bool set(const ww::types::ByteArray& key, const uint32_t val) const;
    bool set(const std::string& key, const uint32_t val) const
    {
        ww::types::ByteArray bkey(key.begin(), key.end());
        return set(bkey, val);
    };


    bool get(const ww::types::ByteArray& key, ww::types::ByteArray& val) const;
    bool get(const std::string& key, ww::types::ByteArray& val) const
    {
        ww::types::ByteArray bkey(key.begin(), key.end());
        return get(bkey, val);
    };

    bool set(const ww::types::ByteArray& key, const ww::types::ByteArray& val) const;
    bool set(const std::string& key, const ww::types::ByteArray& val) const
    {
        ww::types::ByteArray bkey(key.begin(), key.end());
        return set(bkey, val);
    };

    bool get(const std::string& key, std::string& val) const
    {
        ww::types::ByteArray bkey(key.begin(), key.end());
        ww::types::ByteArray bval;
        if (! get(bkey, bval))
            return false;
        val = ww::types::ByteArrayToString(bval);
        return true;
    };

    bool set(const std::string& key, const std::string& val) const
    {
        ww::types::ByteArray bkey(key.begin(), key.end());
        ww::types::ByteArray bval(val.begin(), val.end());

        return set(bkey, bval);
    };
};
