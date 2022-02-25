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
#include "Response.h"
#include "Util.h"
#include "Value.h"

#define STATE_REFERENCE_SCHEMA                  \
    "{"                                         \
        SCHEMA_KW(contract_id,"") ","           \
        SCHEMA_KW(state_hash,"")                \
    "}"

namespace ww
{
namespace value
{

    class StateReference
    {
    public:
        std::string contract_id_;
        std::string state_hash_; // base64 encoded hash

        bool deserialize(const ww::value::Object& reference);
        bool serialize(ww::value::Value& serialized_reference) const;

        // StateReference methods
        bool add_to_response(Response& rsp) const;
        bool set_from_environment(const Environment& env)
        {
            contract_id_ = env.contract_id_;
            state_hash_ = env.state_hash_;
            return true;
        }


        StateReference(
            const StateReference& reference)
            : contract_id_(reference.contract_id_), state_hash_(reference.state_hash_) {};

        StateReference(
            const std::string& contract_id = "",
            const std::string& state_hash = "")
            : contract_id_(contract_id), state_hash_(state_hash) {};

        StateReference(
            const Environment& env)
            : contract_id_(env.contract_id_), state_hash_(env.state_hash_) {};

    };

};
}
