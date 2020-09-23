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

#define SCHEMA_KW(kw,v) "\"" #kw "\":" #v
