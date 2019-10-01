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

#include <stdio.h>
#include <stdint.h>

#include "StringArray.h"

class KeyValueStore
{
    const StringArray prefix_;
    bool make_key(const StringArray& key, StringArray& prefixed_key) const;

public:
    KeyValueStore(const char* prefix) : prefix_(prefix) {};

    bool get(const StringArray& key, uint32_t& val) const;
    bool set(const StringArray& key, const uint32_t val) const;

    bool get(const StringArray& key, StringArray& val) const;
    bool set(const StringArray& key, const StringArray& val) const;
};
