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

#include <string>

#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Types.h"
#include "Util.h"

#define ASSERT_INITIALIZED(_rsp)                                \
    do {                                                        \
        if (! ww::contract::base::is_initialized())    \
            return _rsp.error("contract is not initialized");   \
    } while (0)

#define ASSERT_UNINITIALIZED(_rsp)                                      \
    do {                                                                \
        if (ww::contract::base::is_initialized())              \
            return _rsp.error("contract is already initialized");       \
    } while (0)

#define ASSERT_SENDER_IS_OWNER(_env, _rsp)                              \
    do {                                                                \
        std::string owner;                                              \
        ASSERT_SUCCESS(_rsp, ww::contract::base::get_owner(owner), "failed to retrieve owner"); \
        if (_env.originator_id_ != owner)                               \
            return _rsp.error("only the owner may invoke this method"); \
    } while (0)

namespace ww
{
namespace contract
{
namespace base
{
    // this module defines several contract methods and associated utility functions
    // that are shared between asset contracts, specifically, the methods create
    // an ecdsa key pair

    // common function to initialize state for issuer authority use
    bool initialize_contract(const Environment& env);

    // common contract methods
    bool get_verifying_key(const Message& msg, const Environment& env, Response& rsp);
    bool get_encryption_key(const Message& msg, const Environment& env, Response& rsp);

    // utility functions
    bool mark_initialized(void);
    bool is_initialized(void);

    bool get_verifying_key(std::string& verifying_key);
    bool get_signing_key(std::string& signing_key);

    bool get_encryption_key(std::string& encryption_key);
    bool get_decryption_key(std::string& decryption_key);

    bool set_owner(const std::string& owner);
    bool get_owner(std::string& owner);

}; // contract_base
}; // asset
}; // ww
