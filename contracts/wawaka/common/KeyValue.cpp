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

#include <malloc.h>
#include <stdint.h>
#include <string.h>

#include "Types.h"

#include "KeyValue.h"
#include "Util.h"
#include "WasmExtensions.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// CLASS: KeyValueStore
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::make_key(const ww::types::ByteArray& key, ww::types::ByteArray& prefixed_key) const
{
    prefixed_key.clear();
    if (prefix_.size() > 0)
    {
        prefixed_key.insert(prefixed_key.end(), prefix_.begin(), prefix_.end());
        prefixed_key.push_back((uint8_t)'#');
    }

    prefixed_key.insert(prefixed_key.end(), key.begin(), key.end());

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int KeyValueStore::create(const ww::types::ByteArray& key)
{
    return ::key_value_create(key.data(), key.size());
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int KeyValueStore::open(const ww::types::ByteArray& block_hash, const ww::types::ByteArray& key)
{
    return ::key_value_open(block_hash.data(), block_hash.size(), key.data(), key.size());
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::finalize(const int kv_store_handle, ww::types::ByteArray& block_hash)
{
    uint8_t* datap;
    size_t size;

    if (! ::key_value_finalize(kv_store_handle, &datap, &size))
        return false;

    if (datap == NULL)
    {
        CONTRACT_SAFE_LOG(3, "data allocation failed");
        return false;
    }

    return copy_internal_pointer(block_hash, datap, size);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::get(const ww::types::ByteArray& key, uint32_t& val) const
{
    ww::types::ByteArray prefixed_key;
    if (! make_key(key, prefixed_key))
        return false;

    uint8_t* datap;
    size_t size;

    if (! key_value_get(handle_, prefixed_key.data(), prefixed_key.size(), &datap, &size))
        return false;

    if (datap == NULL)
    {
        CONTRACT_SAFE_LOG(3, "data allocation failed");
        return false;
    }

    if (size != sizeof(uint32_t))
    {
        CONTRACT_SAFE_LOG(3, "wrong size for integer:%lu", size);

        free(datap);
        return false;
    }

    uint32_t* valp = (uint32_t*)datap;

    val = (*valp);
    free(datap);

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::set(const ww::types::ByteArray& key, const uint32_t val) const
{
    ww::types::ByteArray prefixed_key;
    if (! make_key(key, prefixed_key))
        return false;

    return key_value_set(handle_, prefixed_key.data(), prefixed_key.size(), (uint8_t*)&val, sizeof(val));
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::get(const ww::types::ByteArray& key, ww::types::ByteArray& val) const
{
    ww::types::ByteArray prefixed_key;
    if (! make_key(key, prefixed_key))
        return false;

    uint8_t* datap;
    size_t size;

    if (! key_value_get(handle_, prefixed_key.data(), prefixed_key.size(), &datap, &size))
        return false;

    // this should not happen if the result was true
    if (datap == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function key_value_get")
        return false;
    }

    return copy_internal_pointer(val, datap, size);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::set(const ww::types::ByteArray& key, const ww::types::ByteArray& val) const
{
    ww::types::ByteArray prefixed_key;
    if (! make_key(key, prefixed_key))
        return false;

    return key_value_set(handle_, prefixed_key.data(), prefixed_key.size(), val.data(), val.size());
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::privileged_get(const ww::types::ByteArray& key, ww::types::ByteArray& val)
{
    uint8_t* datap;
    size_t size;

    if (! privileged_key_value_get(key.data(), key.size(), &datap, &size))
        return false;

    // this should not happen if the result was true
    if (datap == NULL)
    {
        CONTRACT_SAFE_LOG(3, "invalid pointer from extension function key_value_get")
        return false;
    }

    return copy_internal_pointer(val, datap, size);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::privileged_get(const ww::types::ByteArray& key, uint32_t& val)
{
    ww::types::ByteArray _value;
    if (! KeyValueStore::privileged_get(key, _value))
        return false;

    if (_value.size() != sizeof(uint32_t))
    {
        CONTRACT_SAFE_LOG(3, "wrong size for integer:%lu", _value.size());
        return false;
    }

    val = *(uint32_t*)_value.data();
    return true;
}
