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
static KeyValueStore value_store("values");

const StringArray owner_key("owner");
const StringArray test_key("test");

// -----------------------------------------------------------------
// NAME: originator_is_owner
// -----------------------------------------------------------------
static bool originator_is_owner(const Environment& env, Response& rsp)
{
    // verify that the owner stored in state is the originator
    StringArray owner;
    if (! meta_store.get(owner_key, owner))
    {
        rsp.error("failed to retrieve owner metadata");
        return false;
    }

    const StringArray originator(env.originator_id_);
    if (! owner.equal(originator))
    {
        rsp.error("only the creator can inc the value");
        return false;
    }

    return true;
}

// -----------------------------------------------------------------
// NAME: initialize_contract
// -----------------------------------------------------------------
bool initialize_contract(const Environment& env, Response& rsp)
{
    // save owner information
    const StringArray owner_val(env.creator_id_);

    if (! meta_store.set(owner_key, owner_val))
        return rsp.error("failed to save creator metadata");

    // create the value and save it to state
    const uint32_t value = 0;

    if (! value_store.set(test_key, value))
        return rsp.error("failed to create the test key");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// NAME: inc_value
// -----------------------------------------------------------------
bool inc_value(const Message& msg, const Environment& env, Response& rsp)
{
    if (! originator_is_owner(env, rsp))
        return false;

    // get the value and increment it
    uint32_t value;
    if (! value_store.get(test_key, value))
        return rsp.error("no such key");

    value += 1;
    if (! value_store.set(test_key, value))
        return rsp.error("failed to save the new value");

    ww::value::Number v((double)value);
    return rsp.value(v, true);
}

// -----------------------------------------------------------------
// NAME: get_value
// -----------------------------------------------------------------
bool get_value(const Message& msg, const Environment& env, Response& rsp)
{
    if (! originator_is_owner(env, rsp))
        return false;

    // get the value
    uint32_t value;
    if (! value_store.get(test_key, value))
        return rsp.error("no such key");

    ww::value::Number v((double)value);
    return rsp.value(v, false);
}

contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(inc_value),
    CONTRACT_METHOD(get_value),
    { NULL, NULL }
};
