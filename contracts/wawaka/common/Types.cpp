/* Copyright 2018 Intel Corporation
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

#include <algorithm>
#include <string>
#include <vector>

#include "Types.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Simple conversion from ByteArray to std::string
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::string ww::types::ByteArrayToString(const ww::types::ByteArray& inArray)
{
    std::string outString;
    std::transform(inArray.begin(), inArray.end(), std::back_inserter(outString),
                   [](unsigned char c) -> char { return (char)c; });

    return outString;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Conversion from byte array to string array
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ww::types::ByteArrayToStringArray(
    const ww::types::ByteArray& inByteArray,
    ww::types::StringArray& outStringArray)
{
    outStringArray.resize(0);
    std::transform(inByteArray.begin(), inByteArray.end(), std::back_inserter(outStringArray),
                   [](unsigned char c) -> char { return (char)c; });
}

ww::types::StringArray ww::types::ByteArrayToStringArray(const ww::types::ByteArray& inByteArray)
{
    ww::types::StringArray outStringArray(0);
    ww::types::ByteArrayToStringArray(inByteArray, outStringArray);
    return outStringArray;
}
