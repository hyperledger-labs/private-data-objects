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
#include "state.h"
#include "types.h"
#include <string>
#include "error.h"
#include "StateUtils.h"
#include "StateBlock.h"
#include "state_kv.h"
#include "_kv_gen.h"

#if _UNTRUSTED_ == 1
    #include <stdio.h>
    #define SAFE_LOG(LEVEL, FMT, ...) printf(FMT, ##__VA_ARGS__)
#else // __UNTRUSTED__ == 0
    #define SAFE_LOG(LEVEL, FMT, ...)
#endif // __UNTRUSTED__

namespace pstate = pdo::state;

extern pdo::state::Basic_KV* kv_;

#define MAX_BIG_VALUE_LOG2_SIZE 26

void test_state_kv() {
    ByteArray emptyId;
    SAFE_LOG(PDO_LOG_DEBUG, "statekv init empty state kv");
    ByteArray state_encryption_key_(16, 0);
    size_t test_key_length = TEST_KEY_STRING_LENGTH;
    ByteArray id;

    try
    {
        SAFE_LOG(PDO_LOG_INFO, "create empty KV store\n");
        pstate::State_KV skv(emptyId, state_encryption_key_, test_key_length);
        kv_ = &skv;
        SAFE_LOG(PDO_LOG_INFO, "start Put generator\n");
        _test_kv_put();
        kv_->Uninit(id);
        kv_ = NULL;
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
        pstate::State_KV skv(id, state_encryption_key_, test_key_length);
        kv_ = &skv;
        SAFE_LOG(PDO_LOG_INFO, "start Get generator\n");
        _test_kv_get();
        bool exception_caught = false;
        try
        {
            //this should fail
            std::string missing_key(test_key_length, 'z');
            _kv_get(missing_key, "this key does not exist");
        }
        catch(...)
        {
            SAFE_LOG(PDO_LOG_INFO, "expected exception, key not found\n");
            exception_caught = true;
        }
        if(! exception_caught) {
            SAFE_LOG(PDO_LOG_ERROR, "exception not caught\n");
            throw;
        }
        kv_->Uninit(id);
        kv_ = NULL;
        SAFE_LOG(PDO_LOG_ERROR, "uninit, KV id: %s\n", ByteArrayToHexEncodedString(id).c_str());
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KV Get operation");
        throw;
    }

    try
    {
        SAFE_LOG(PDO_LOG_INFO, "reopen KV store, id: %s\n", ByteArrayToHexEncodedString(id).c_str());
        pstate::State_KV skv(id, state_encryption_key_, test_key_length);
        kv_ = &skv;
        SAFE_LOG(PDO_LOG_INFO, "start big value test\n");
        for(int i=1; i<MAX_BIG_VALUE_LOG2_SIZE; i++) {
            size_t value_size = (1<<i);
            std::string big_string(value_size, 'a');
            std::string big_string_key = std::to_string(i);
            int prefix_pad_length = TEST_KEY_STRING_LENGTH - big_string_key.length();
            prefix_pad_length = (prefix_pad_length<0?0:prefix_pad_length);
            big_string_key.insert(0, prefix_pad_length, '0');
            SAFE_LOG(PDO_LOG_INFO, "Testing put/get value size %lu, string size %lu\n", value_size, big_string.length());

            try
            {
                _kv_put(big_string_key, big_string);
            }
            catch (...)
            {
                SAFE_LOG(PDO_LOG_ERROR, "error testing KV Put operation on big value");
                throw;
            }
            try
            {
                _kv_get(big_string_key, big_string);
            }
            catch (...)
            {
                SAFE_LOG(PDO_LOG_ERROR, "error testing KV Get operation on big value");
                throw;
            }
        }
        kv_->Uninit(id);
        kv_ = NULL;
        SAFE_LOG(PDO_LOG_ERROR, "uninit, KV id: %s\n", ByteArrayToHexEncodedString(id).c_str());
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KV on big value");
        throw;
    }

    try
    {
        SAFE_LOG(PDO_LOG_INFO, "start big value test (default fixed kv keys)\n");
        pstate::State_KV skv(emptyId, state_encryption_key_);
        kv_ = &skv;
        for(int i=1; i<MAX_BIG_VALUE_LOG2_SIZE; i++) {
            size_t value_size = (1<<i);
            std::string big_string(value_size, 'a');
            std::string big_string_key = std::to_string(i);
            SAFE_LOG(PDO_LOG_INFO, "Testing put/get value size %lu, string size %lu\n", value_size, big_string.length());

            try
            {
                _kv_put(big_string_key, big_string);
            }
            catch (...)
            {
                SAFE_LOG(PDO_LOG_ERROR, "error testing KV Put operation on big value");
                throw;
            }
            try
            {
                _kv_get(big_string_key, big_string);
            }
            catch (...)
            {
                SAFE_LOG(PDO_LOG_ERROR, "error testing KV Get operation on big value");
                throw;
            }
        }
        kv_->Uninit(id);
        kv_ = NULL;
        SAFE_LOG(PDO_LOG_ERROR, "uninit, KV id: %s\n", ByteArrayToHexEncodedString(id).c_str());
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KV on big value");
        throw;
    }
}
