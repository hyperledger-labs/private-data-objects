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

#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "StringArray.h"

#define ASSERT_INITIALIZED(_rsp)                                \
    do {                                                        \
        if (! ww::exchange::exchange_base::is_initialized())    \
            return _rsp.error("contract is not initialized");   \
    } while (0)

#define ASSERT_UNINITIALIZED(_rsp)                                      \
    do {                                                                \
        if (ww::exchange::exchange_base::is_initialized())              \
            return _rsp.error("contract is already initialized");       \
    } while (0)

namespace ww
{
namespace exchange
{
namespace exchange_base
{
    // this module defines several contract methods and associated utility functions
    // that are shared between exchange contracts, specifically, the methods create
    // an ecdsa key pair

    // common function to initialize state for issuer authority use
    bool initialize_contract(const Environment& env, Response& rsp);
    bool get_verifying_key(const Message& msg, const Environment& env, Response& rsp);

    // utility functions
    bool mark_initialized(void);
    bool is_initialized(void);

    bool get_verifying_key(StringArray& verifying_key);
    bool get_signing_key(StringArray& signing_key);

}; // exchange_base
}; // exchange
}; // ww
