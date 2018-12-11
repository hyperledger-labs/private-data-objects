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

#include "state.h"
#include "types.h"
#include <string>
#include "error.h"
#include "_kv_gen.h"
#include "StateUtils.h"

#if _UNTRUSTED_ == 1
    #include <stdio.h>
    #define SAFE_LOG(LEVEL, FMT, ...) printf(FMT, ##__VA_ARGS__)
#else // __UNTRUSTED__ == 0
    #define SAFE_LOG(LEVEL, FMT, ...)
#endif // __UNTRUSTED__

namespace pstate = pdo::state;

extern pdo::state::Basic_KV* kv_;

#define MAX_BIG_VALUE_LOG2_SIZE 24

#define MIN_KEY_LENGTH ((1<<14) - (1<<8))
#define MAX_KEY_LENGTH (1<<14)

void test_state_kv() {
    ByteArray emptyId;
    SAFE_LOG(PDO_LOG_DEBUG, "statekv init empty state kv\n");
    const ByteArray state_encryption_key_(16, 0);
    size_t test_key_length = TEST_KEY_STRING_LENGTH;
    ByteArray id;

//################ TEST PUT ###########################################################################################
    try
    {
        SAFE_LOG(PDO_LOG_INFO, "create empty KV store\n");
        pstate::State_KV skv(state_encryption_key_);
        kv_ = &skv;
        SAFE_LOG(PDO_LOG_INFO, "start Put generator\n");
        _test_kv_put();
        kv_->Finalize(id);
        kv_ = NULL;
        SAFE_LOG(PDO_LOG_INFO, "uninit, KV id: %s\n", ByteArrayToHexEncodedString(id).c_str());
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KV Put operation");
        throw;
    }

//############### TEST GET ############################################################################################
    try
    {
        SAFE_LOG(PDO_LOG_INFO, "reopen KV store, id: %s\n", ByteArrayToHexEncodedString(id).c_str());
        pstate::State_KV skv(id, state_encryption_key_);
        kv_ = &skv;
        SAFE_LOG(PDO_LOG_INFO, "start Get generator\n");
        _test_kv_get();
        SAFE_LOG(PDO_LOG_INFO, "end Get generator\n");

        //######### TEST MISSING KEY ##################################################################################
        bool exception_caught = false;
        try
        {
            //this should fail
            SAFE_LOG(PDO_LOG_INFO, "Test missing key");
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
        kv_->Finalize(id);
        kv_ = NULL;
        SAFE_LOG(PDO_LOG_INFO, "uninit, KV id: %s\n", ByteArrayToHexEncodedString(id).c_str());
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KV Get operation");
        throw;
    }

//############### TEST VARIABLE LENGTH KEYS ###########################################################################
    try
    {
        SAFE_LOG(PDO_LOG_INFO, "start variable key length test (increasing)\n");
        pstate::State_KV skv(state_encryption_key_);
        kv_ = &skv;
        for(int i=MIN_KEY_LENGTH; i<=MAX_KEY_LENGTH; i++) {
            size_t key_size = i;
            std::string variable_key(key_size, 'a');
            std::string value(10000, 'a');
            try
            {
                _kv_put(variable_key, value);
            }
            catch (...)
            {
                SAFE_LOG(PDO_LOG_ERROR, "error testing KV Put operation on variable key len");
                throw;
            }
            try
            {
                _kv_get(variable_key, value);
            }
            catch (...)
            {
                SAFE_LOG(PDO_LOG_ERROR, "error testing KV Get operation on variable key len");
                throw;
            }
        }
        kv_->Finalize(id);
        kv_ = NULL;
        SAFE_LOG(PDO_LOG_INFO, "uninit, KV id: %s\n", ByteArrayToHexEncodedString(id).c_str());
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KV on variable key len");
        throw;
    }

    try
    {
        SAFE_LOG(PDO_LOG_INFO, "start variable key length test (decreasing)\n");
        pstate::State_KV skv(state_encryption_key_);
        kv_ = &skv;
        for(int i=MAX_KEY_LENGTH; i>=MIN_KEY_LENGTH; i--) {
            size_t key_size = i;
            std::string variable_key(key_size, 'a');
            std::string value = std::to_string(i);
            try
            {
                _kv_put(variable_key, value);
            }
            catch (...)
            {
                SAFE_LOG(PDO_LOG_ERROR, "error testing KV Put operation on variable key len");
                throw;
            }
            try
            {
                _kv_get(variable_key, value);
            }
            catch (...)
            {
                SAFE_LOG(PDO_LOG_ERROR, "error testing KV Get operation on variable key len");
                throw;
            }
        }
        kv_->Finalize(id);
        kv_ = NULL;
        SAFE_LOG(PDO_LOG_INFO, "uninit, KV id: %s\n", ByteArrayToHexEncodedString(id).c_str());
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KV on variable key len");
        throw;
    }

//##################### TEST BIG VALUE ################################################################################
    try
    {
        SAFE_LOG(PDO_LOG_INFO, "start big value test\n");
        pstate::State_KV skv(state_encryption_key_);
        kv_ = &skv;
        for(int i=1; i<=MAX_BIG_VALUE_LOG2_SIZE; i++) {
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
        kv_->Finalize(id);
        kv_ = NULL;
        SAFE_LOG(PDO_LOG_INFO, "uninit, KV id: %s\n", ByteArrayToHexEncodedString(id).c_str());
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KV on big value");
        throw;
    }

//################## TEST DELETE ######################################################################################
    try
    {
        SAFE_LOG(PDO_LOG_INFO, "start test delete -- errors expected\n");
        pstate::State_KV skv(state_encryption_key_);
        kv_ = &skv;
        for(int i=0; i<1000; i++) {
            std::string val = std::to_string(i);
            std::string key = std::to_string(i);
            try
            {
                _kv_put(key, val);
                _kv_get(key, val); //double check
            }
            catch (...)
            {
                SAFE_LOG(PDO_LOG_ERROR, "error testing KV Put/Get operation for delete");
                throw;
            }
            _kv_delete(key);
            //######### TEST MISSING KEY ##################################################################################
            bool exception_caught = false;
            try
            {
                //this should fail
                _kv_get(key, val);
            }
            catch(...)
            {
                exception_caught = true;
                SAFE_LOG(PDO_LOG_INFO, "any error is expected!\n");
            }
            if(! exception_caught) {
                SAFE_LOG(PDO_LOG_ERROR, "exception not caught -- key not deleted\n");
                throw;
            }
        }

        kv_->Finalize(id);
        kv_ = NULL;
        SAFE_LOG(PDO_LOG_INFO, "uninit, KV id: %s\n", ByteArrayToHexEncodedString(id).c_str());
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KV on delete\n");
        throw;
    }

//################## TEST INEXISTENT STATE ############################################################################
    try
    {
        SAFE_LOG(PDO_LOG_INFO, "start test inexistent state -- errors expected\n");
        StateBlockId badId(32, 2);
        pstate::State_KV skv(badId, state_encryption_key_);
        //should not get here
        SAFE_LOG(PDO_LOG_ERROR, "error testing inexistent KV\n");
        throw;
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "success, exception caught for inexistent KV\n");
        throw;
    }

    SAFE_LOG(PDO_LOG_INFO, "Test success.\n");
}
