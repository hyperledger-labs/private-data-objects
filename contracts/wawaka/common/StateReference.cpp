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

// -----------------------------------------------------------------
bool ww::value::StateReference::deserialize(const ww::value::Object& reference)
{
    if (! reference.validate_schema(STATE_REFERENCE_SCHEMA))
        return false;

    contract_id_ = reference.get_string("contract_id");
    state_hash_ = reference.get_string("state_hash");
    return true;
}

// -----------------------------------------------------------------
bool ww::value::StateReference::serialize(ww::value::Value& serialized_reference) const
{
    ww::value::Structure reference(STATE_REFERENCE_SCHEMA);
    if (! reference.set_string("contract_id", contract_id_.c_str()))
        return false;
    if (! reference.set_string("state_hash", state_hash_.c_str()))
        return false;

    serialized_reference.set(reference);
    return true;
}

// -----------------------------------------------------------------
bool ww::value::StateReference::add_to_response(Response& rsp) const
{
    return rsp.add_dependency(contract_id_, state_hash_);
}
