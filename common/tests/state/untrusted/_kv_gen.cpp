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

#include "_kv_gen.h"
#include "types.h"
#include "log.h"
#include "pdo_error.h"
#include "error.h"
#include "basic_kv.h"

pdo::state::Basic_KV* kv_;

void _kv_generator(std::string s, unsigned int chars_left, _kv_f pf) {
    int i;
    if(!chars_left) {
        pf(s, VAL_STR);
        return;
    }

    for(i=0;i<10;i++) {
        s.push_back('a' + i);
        _kv_generator(s, chars_left-1, pf);
        s.pop_back();
    }
}

void _kv_put(std::string key, std::string value) {
    ByteArray baKey(key.begin(), key.end());
    ByteArray baValue(value.begin(), value.end());
    kv_->Put(baKey, baValue);
}

void _kv_get(std::string key, std::string expected_value) {
    ByteArray baKey(key.begin(), key.end());
    ByteArray baValue = kv_->Get(baKey);
    std::string value(baValue.begin(), baValue.end());
    if(value != expected_value) {
        SAFE_LOG(PDO_LOG_INFO, "ERROR: val size %lu expected size %lu\n", baValue.size(), expected_value.size());
        ByteArray baExpectedValue(expected_value.begin(), expected_value.end());
        SAFE_LOG(PDO_LOG_INFO, "ERROR: byte arrays differ too (sizes %lu %lu)\n", baExpectedValue.size(), baValue.size());
        SAFE_LOG(PDO_LOG_INFO, "retrieved: %s\n", ByteArrayToHexEncodedString(baValue).c_str());
        SAFE_LOG(PDO_LOG_INFO, "expected : %s\n", ByteArrayToHexEncodedString(baExpectedValue).c_str());
        SAFE_LOG(PDO_LOG_INFO, "ERROR Get %s %s (expected %s)\n", key.c_str(), value.c_str(), expected_value.c_str());
        throw pdo::error::RuntimeError("error: retrieved value and expected value do not match");
    }
}

void _kv_delete(std::string key) {
    ByteArray baKey(key.begin(), key.end());
    kv_->Delete(baKey);
}

void _test_kv_put() {
    _kv_generator("", TEST_KEY_STRING_LENGTH, _kv_put);
}
void _test_kv_get() {
    _kv_generator("", TEST_KEY_STRING_LENGTH, _kv_get);
}
