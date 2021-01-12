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
#include "WasmExtensions.h"

#define SIMPLE_PROPERTY_GET(CLASS, KEY, TYPE)                   \
    bool ww::exchange::CLASS::get_##KEY(TYPE& value) const      \
    {                                                           \
        return get_value(#KEY, value);                          \
    }

#define SIMPLE_PROPERTY_SET(CLASS, KEY, TYPE)                   \
    bool ww::exchange::CLASS::set_##KEY(const TYPE& value)      \
    {                                                           \
        return set_value(#KEY, value);                          \
    }

// macros for getting and setting simple properties with a
// consistent message
#define SAFE_GET(_RSP_, _VAL_, _OBJ_, _KEY_)                    \
    do {                                                        \
        if (! _OBJ_.get_##_KEY_(_VAL_))                         \
            return _RSP_.error("failed to retrieve " #_KEY_);   \
    } while (0)

#define SAFE_SET(_RSP_, _VAL_, _OBJ_, _KEY_)                    \
    do {                                                        \
        if (! _OBJ_.set_##_KEY_(_VAL_))                         \
            return _RSP_.error("failed to store " #_KEY_);      \
    } while (0)

#define SAFE_STRING_ARRAY_GET(_RSP_, _VAL_, _OBJ_, _KEY_)       \
    do {                                                        \
        ww::value::String _v_;                                  \
        if (! _OBJ_.get_##_KEY_(_v_))                           \
            return _RSP_.error("failed to retrieve " #_KEY_);   \
        _VAL_.assign(_v_.get());                                \
    } while (0)

#define SAFE_STRING_ARRAY_SET(_RSP_, _VAL_, _OBJ_, _KEY_)               \
    do {                                                                \
        if (! _VAL_.null_terminated())                                  \
            return _RSP_.error("expected null terminated value for " #_KEY_); \
        ww::value::String _v_((const char*)_VAL_.c_data());             \
        if (! _OBJ_.set_##_KEY_(_v_))                                   \
            return _RSP_.error("failed to store " #_KEY_);              \
    } while (0)

#define SCHEMA_KW(kw,v) "\"" #kw "\":" #v
