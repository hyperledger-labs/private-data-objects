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

#pragma once

#include <string>

//the test generates 10^TEST_KEY_LENGTH keys
#define TEST_KEY_STRING_LENGTH 2

#define VAL_STR "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"

typedef void (*_kv_f)(std::string key, std::string value);

void _kv_generator(std::string s, unsigned int chars_left, _kv_f pf);
void _kv_put(std::string key, std::string value);
void _kv_get(std::string key, std::string expected_value);
void _test_kv_put();
void _test_kv_get();
