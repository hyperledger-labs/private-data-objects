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
#include <string.h>

class StringArray
{
public:
    uint8_t *value_;
    size_t size_;

    StringArray(void);
    StringArray(const size_t size);
    StringArray(const uint8_t* buffer, size_t size);
    StringArray(const char* buffer);
    StringArray(const StringArray& value);
    ~StringArray(void);

    bool clear(void);
    bool resize(const size_t size);
    bool assign(const uint8_t* buffer, size_t size);
    bool assign(const char* buffer);
    bool set(uint8_t v, size_t p);
    bool take(uint8_t* buffer, size_t size);
    bool equal(const StringArray& sarray) const;
    bool null_terminated(void) const;

    const size_t size(void) const;
    uint8_t* data(void);

    const uint8_t* c_data(void) const;
};
