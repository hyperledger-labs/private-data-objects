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

#include "basic_kv.h"
#include "serial_kv.h"
#include "types.h"
#include <string>
#include "sal.h"
#include "error.h"

#if _UNTRUSTED_ == 1
    #include <stdio.h>
    #define SAFE_LOG(LEVEL, FMT, ...) printf(FMT, ##__VA_ARGS__)
#else // __UNTRUSTED__ == 0
    #define SAFE_LOG(LEVEL, FMT, ...)
#endif // __UNTRUSTED__


//the test generates 10^TEST_KEY_LENGTH keys
#define TEST_KEY_LENGTH 2 

pdo::state::Basic_KV* kv_;

typedef void (*_kv_f)(std::string key, std::string value);

void _kv_generator(std::string s, unsigned int chars_left, _kv_f pf) {
    int i;
    if(!chars_left) {
        pf(s, "012345678901234567890123456789");
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
    SAFE_LOG("Put %s %s\n", key.c_str(), value.c_str());
    kv_->Put(baKey, baValue);
}

void _kv_get(std::string key, std::string expected_value) {
    ByteArray baKey(key.begin(), key.end());
    ByteArray baValue = kv_->Get(baKey);
    std::string value(baValue.begin(), baValue.end());    
    if(value != expected_value) {
        SAFE_LOG(PDO_LOG_INFO, "ERROR Get %s %s (expected %s)\n", key.c_str(), value.c_str(), expected_value.c_str());
        throw pdo::error::RuntimeError("error: retrieved value and expected value do not match");
    }
    SAFE_LOG(PDO_LOG_INFO, "SUCCESS Get %s %s (expected %s)\n", key.c_str(), value.c_str(), expected_value.c_str());
}

void _test_kv_put() {
    _kv_generator("", TEST_KEY_LENGTH, _kv_put);
}
void _test_kv_get() {
    _kv_generator("", TEST_KEY_LENGTH, _kv_get);
}

void test_kv() {
    SAFE_LOG(PDO_LOG_INFO, "init SAL\n");
    g_sal.init(*(new ByteArray()));

    ByteArray id;

    try 
    {
        SAFE_LOG(PDO_LOG_INFO, "create empty KV store\n");
        kv_ = new pdo::state::Serial_KV(id);
        SAFE_LOG(PDO_LOG_INFO, "start Put generator\n");
        _test_kv_put();
        kv_->Uninit(id);
        delete kv_;
        SAFE_LOG(PDO_LOG_ERROR, "uninit, KV id: %s\n", ByteArrayToHexEncodedString(id).c_str());
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KV Put operation");
        throw;
    }

    try
    {
        SAFE_LOG(PDO_LOG_INFO, "reopen KV store, id: %s\n", ByteArrayToHexEncodedString(id).c_str());
        kv_ = new pdo::state::Serial_KV(id);
        SAFE_LOG(PDO_LOG_INFO, "start Get generator\n");
        _test_kv_get();
        try
        {
            //this should fail
            _kv_get("bruno", "bruno");
        }
        catch(...)
        {
            SAFE_LOG(PDO_LOG_INFO, "expected exception, key not found\n");
        }
        kv_->Uninit(id);
        SAFE_LOG(PDO_LOG_ERROR, "uninit, KV id: %s\n", ByteArrayToHexEncodedString(id).c_str());
        delete kv_;
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KV Get operation");
        throw;
    }

    g_sal.uninit(&id);
    SAFE_LOG(PDO_LOG_INFO, "uninit SAL, id: %s\n", ByteArrayToHexEncodedString(id).c_str());
}
