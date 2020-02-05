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

#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "Dispatch.h"

#include "KeyValue.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "StringArray.h"
#include "Value.h"
#include "WasmExtensions.h"

static KeyValueStore meta_store("meta");

const StringArray owner_key("owner");

// -----------------------------------------------------------------
// NAME: initialize_contract
// -----------------------------------------------------------------
bool initialize_contract(const Environment& env, Response& rsp)
{
    // save owner information
    const StringArray owner_val(env.creator_id_);

    if (! meta_store.set(owner_key, owner_val))
        return rsp.error("failed to save creator metadata");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// NAME: environment_test
// -----------------------------------------------------------------
bool environment_test(const Message& msg, const Environment& env, Response& rsp)
{
    ww::value::Object o;
    ww::value::String s("");

    s.set(env.contract_id_);
    o.set_value("ContractID", s);

    s.set(env.creator_id_);
    o.set_value("CreatorID", s);

    s.set(env.originator_id_);
    o.set_value("OriginatorID", s);

    s.set(env.state_hash_);
    o.set_value("StateHash", s);

    s.set(env.message_hash_);
    o.set_value("MessageHash", s);

    s.set(env.contract_code_name_);
    o.set_value("ContractCodeName", s);

    s.set(env.contract_code_hash_);
    o.set_value("ContractCodeHash", s);

    return rsp.value(o, false);
}

// -----------------------------------------------------------------
// NAME: echo_test
// -----------------------------------------------------------------
bool echo_test(const Message& msg, const Environment& env, Response& rsp)
{
    ww::value::String message(msg.get_string("message"));
    return rsp.value(message, false);
}

// -----------------------------------------------------------------
// NAME: fail_test
// -----------------------------------------------------------------
bool fail_test(const Message& msg, const Environment& env, Response& rsp)
{
    return rsp.error("this test should fail");
}

// -----------------------------------------------------------------
// NAME: depends_test
// -----------------------------------------------------------------
bool dependency_test(const Message& msg, const Environment& env, Response& rsp)
{
    ww::value::String contract_id(msg.get_string("ContractID"));
    ww::value::String state_hash(msg.get_string("StateHash"));

    rsp.add_dependency(env.contract_id_, env.state_hash_);
    return rsp.success(false);
}

contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(environment_test),
    CONTRACT_METHOD(echo_test),
    CONTRACT_METHOD(fail_test),
    CONTRACT_METHOD(dependency_test),
    { NULL, NULL }
};
