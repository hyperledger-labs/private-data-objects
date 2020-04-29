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

#include <stdint.h>
#include <string.h>

#include "StringArray.h"
#include "WasmExtensions.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// CLASS: StringArray
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
StringArray::StringArray(void)
{
    size_ = 0;
    value_ = NULL;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
StringArray::StringArray(const size_t size)
{
    size_ = 0;
    value_ = NULL;

   (void) resize(size);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
StringArray::StringArray(const uint8_t* buffer, size_t size)
{
    size_ = size;
    value_ = new uint8_t[size_];
    if (value_ == NULL)
        return;

    memcpy(value_, buffer, size_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
StringArray::StringArray(const char* buffer)
{
    size_ = 0;
    value_ = NULL;

    (void) assign(buffer);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Copy constructor
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
StringArray::StringArray(const StringArray& value)
{
    size_ = value.size_;
    value_ = new uint8_t[size_];
    if (value_ == NULL)
        return;

    memcpy(value_, value.value_, size_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
StringArray::~StringArray(void)
{
    if (value_ != NULL)
        delete value_;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool StringArray::resize(const size_t size)
{
    if (value_ != NULL)
        delete value_;

    size_ = size;
    value_ = new uint8_t[size_];
    if (value_ == NULL)
        return false;

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool StringArray::clear(void)
{
    if (value_ != NULL)
        delete value_;

    size_ = 0;
    value_ = NULL;

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool StringArray::assign(const uint8_t* buffer, size_t size)
{
    if (buffer == NULL)
        return false;

    if (size == 0)
        return false;

    if (! resize(size))
        return false;

    memcpy(value_, buffer, size_);
    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool StringArray::assign(const char* buffer)
{
    if (buffer == NULL)
        return false;

    size_t size;
    const char *b;

    for (b = buffer, size = 0; *b; b++, size++) ;

    if (! resize(size + 1))
        return false;

    memcpy(value_, (uint8_t*)buffer, size);
    value_[size] = 0;

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool StringArray::set(uint8_t v, size_t p)
{
    if (value_ == NULL)
        return false;

    if (p < size_)
    {
        value_[p] = v;
        return true;
    }

    return false;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool StringArray::take(uint8_t* buffer, size_t size)
{
    if (buffer == NULL)
        return false;

    if (size == 0)
        return false;

    if (value_ != NULL)
        delete value_;

    size_ = size;
    value_ = buffer;

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool StringArray::equal(const StringArray& sarray) const
{
    if (size_ != sarray.size_)
        return false;

    return (memcmp(value_, sarray.value_, size_) == 0);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool StringArray::null_terminated(void) const
{
    if (value_ == NULL || size_ == 0)
        return false;

    return (value_[size_ - 1] == 0);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
const size_t StringArray::size(void) const
{
    return size_;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
uint8_t* StringArray::data(void)
{
    return value_;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
const uint8_t* StringArray::c_data(void) const
{
    return value_;
}
