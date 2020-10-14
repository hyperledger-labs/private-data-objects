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
#include "Response.h"
#include "Value.h"

#include "Common.h"

#define STATE_REFERENCE_SCHEMA "{"              \
    SCHEMA_KW(contract_id,"") ","             \
    SCHEMA_KW(state_hash,"")                  \
    "}"

namespace ww
{
namespace exchange
{

    class StateReference : public ww::value::Structure
    {
    public:
        bool get_contract_id(ww::value::String& value) const;
        bool get_state_hash(ww::value::String& value) const;

        bool set_contract_id(const ww::value::String& value);
        bool set_state_hash(const ww::value::String& value);

        bool validate(void) const;

        bool add_to_response(Response& rsp) const;

        StateReference(void);
        StateReference(const Environment& env);
    };

};
}
