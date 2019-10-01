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

#include "KeyValue.h"
#include "StringArray.h"
#include "WasmExtensions.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// CLASS: KeyValueStore
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::make_key(const StringArray& key, StringArray& prefixed_key) const
{
    if (! prefixed_key.resize(prefix_.size() + key.size() + 1))
        return false;

    // note that this key will include the null terminators, thats fine
    // since keys are binary anyway
    uint8_t *buffer = prefixed_key.data();
    memcpy((void*)buffer, (void*)prefix_.c_data(), prefix_.size());
    buffer[prefix_.size()] = '#';
    memcpy((void*)(buffer + (prefix_.size() + 1)), (void*)key.c_data(), key.size());

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::get(const StringArray& key, uint32_t& val) const
{
    StringArray prefixed_key(1);
    make_key(key, prefixed_key);

    uint8_t* datap;
    size_t size;

    if (! key_value_get(prefixed_key.c_data(), prefixed_key.size(), &datap, &size))
        return false;

    if (size != sizeof(uint32_t))
    {
        CONTRACT_SAFE_LOG(3, "wrong size for integer:%lu", size);
        return false;
    }

    uint32_t* valp = (uint32_t*)datap;

    val = (*valp);
    free(datap);

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::set(const StringArray& key, const uint32_t val) const
{
    StringArray prefixed_key(1);
    make_key(key, prefixed_key);

    return key_value_set(prefixed_key.c_data(), prefixed_key.size(), (uint8_t*)&val, sizeof(val));
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::get(const StringArray& key, StringArray& val) const
{
    StringArray prefixed_key(1);
    make_key(key, prefixed_key);

    uint8_t* datap;
    size_t size;

    if (! key_value_get(prefixed_key.c_data(), prefixed_key.size(), &datap, &size))
        return false;

    val.take(datap, size);
    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool KeyValueStore::set(const StringArray& key, const StringArray& val) const
{
    StringArray prefixed_key(1);
    make_key(key, prefixed_key);

    return key_value_set(prefixed_key.c_data(), prefixed_key.size(), val.c_data(), val.size());
}
