/* Copyright 2023 Intel Corporation
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

#include <assert.h>
#include <string>

#include "error.h"
#include "log.h"
#include "pdo_error.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
namespace pdo {
    namespace error {
        class TestError : public pdo::error::Error
        {
        public:
            explicit TestError(const std::string& msg) : pdo::error::Error(PDO_ERR_RUNTIME, msg) {};
        };
    };
};

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define LOG_FAILURE(_TEST_, _EXCEPTION_, _MSG_) \
    SAFE_LOG(PDO_LOG_ERROR, "TEST FAILED [%s] %s at %s:%d\n%s\n",_TEST_, _EXCEPTION_, __FILE__,__LINE__, _MSG_)

#define LOG_SUCCESS(_TEST_) \
    SAFE_LOG(PDO_LOG_INFO, "TEST SUCCEEDED [%s]\n", _TEST_)

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define RUNTEST(_EXPR_, _TEST_)                         \
    try {                                               \
        if (! _EXPR_ ) return false;                    \
    }                                                   \
    catch (const pdo::error::ValueError& e) {           \
        LOG_FAILURE(_TEST_, "ValueError", e.what());    \
        return false;                                   \
    }                                                   \
    catch (const pdo::error::RuntimeError& e) {         \
        LOG_FAILURE(_TEST_, "RuntimeError", e.what());  \
        return false;                                   \
    }                                                   \
    catch (const pdo::error::TestError& e) {            \
        LOG_FAILURE(_TEST_, "TestError", e.what());     \
        return false;                                   \
    }                                                   \
    catch (const std::exception& e) {                   \
        LOG_FAILURE(_TEST_, "Unexpected", e.what());    \
        return false;                                   \
    }                                                   \
    LOG_SUCCESS(_TEST_);


#define ASSERT_TRUE(_EXPR_) \
    pdo::error::ThrowIf<pdo::error::TestError>(! ( _EXPR_ ), "\"" #_EXPR_ "\"")

#define ASSERT_FALSE(_EXPR_) \
    pdo::error::ThrowIf<pdo::error::TestError>(( _EXPR_ ), "\"" #_EXPR_ "\"")

#define ASSERT_UNREACHABLE() \
    pdo::error::ThrowIf<pdo::error::TestError>( true, "failed to generate exception")
