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

#include <stdlib.h>
#include <string.h>

#include "jsonvalue.h"
#include "parson.h"

#include "Response.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Response::Response(void)
{
    value_ = json_value_init_object();
    expected_value_type_ = (value_ == NULL ? JSONError : json_value_get_type(value_));

    ww::value::Boolean status(true);
    ww::value::Boolean response(true);
    ww::value::Boolean state_changed(false);
    ww::value::Array dependencies;

    set_value("Status", status);
    set_value("Response", response);
    set_value("StateChanged", state_changed);
    set_value("Dependencies", dependencies);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool Response::set_response(const ww::value::Value& response)
{
    char* serialized_response = response.serialize();
    if (serialized_response == NULL)
        return false;

    ww::value::String v(serialized_response);
    free(serialized_response);

    return set_value("Response", v);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool Response::set_state_changed(bool state_changed)
{
    ww::value::Boolean v(state_changed);
    return set_value("StateChanged", v);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool Response::set_status(bool status)
{
    ww::value::Boolean v(status);
    return set_value("Status", v);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool Response::add_dependency(const char* contract_id, const char* state_hash)
{
    ww::value::Object d;
    ww::value::String contract_id_value(contract_id);
    ww::value::String state_hash_value(state_hash);

    d.set_value("ContractID", contract_id_value);
    d.set_value("StateHash", state_hash_value);

    ww::value::Array a;
    if (! get_value("Dependencies", a))
        return false;

    a.append_value(d);

    return set_value("Dependencies", a);
}
