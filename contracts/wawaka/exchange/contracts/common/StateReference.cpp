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

#include "StateReference.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::exchange::StateReference
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static const ww::exchange::StateReference state_reference_schema;

// -----------------------------------------------------------------
ww::exchange::StateReference::StateReference(void) :
    ww::value::Structure(STATE_REFERENCE_SCHEMA)
{
    return;
}

ww::exchange::StateReference::StateReference(const Environment& env) :
    ww::value::Structure(STATE_REFERENCE_SCHEMA)
{
    const ww::value::String contract_id(env.contract_id_);
    set_contract_id(contract_id);

    const ww::value::String state_hash(env.state_hash_);
    set_state_hash(state_hash);
}

// -----------------------------------------------------------------
SIMPLE_PROPERTY_GET(StateReference, contract_id, ww::value::String);
SIMPLE_PROPERTY_GET(StateReference, state_hash, ww::value::String);

SIMPLE_PROPERTY_SET(StateReference, contract_id, ww::value::String);
SIMPLE_PROPERTY_SET(StateReference, state_hash, ww::value::String);

// -----------------------------------------------------------------
bool ww::exchange::StateReference::validate(void) const
{
    // should add a check to make sure that the contract_id and state_hash
    // have the correct format

    return validate_schema(state_reference_schema);
}

// -----------------------------------------------------------------
bool ww::exchange::StateReference::add_to_response(Response& rsp) const
{
    if (! validate())
        return false;

    const char* contract_id = get_string("contract_id");
    const char* state_hash = get_string("state_hash");

    return rsp.add_dependency(contract_id, state_hash);
}
