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

static KeyValueStore value_store("values");
const StringArray test_key("test");

bool initialize(const Message& msg, const Environment& env, Response& rsp)
{
    const uint32_t value = 0;

    if (! value_store.set(test_key, value))
        return rsp.error("failed to create the test key");

    return rsp.success(true);
}

bool inc_value(const Message& msg, const Environment& env, Response& rsp)
{
    uint32_t value;
    if (! value_store.get(test_key, value))
        return rsp.error("no such key");

    value += 1;
    if (! value_store.set(test_key, value))
        return rsp.error("failed to save the new value");

    ww::value::Number v((double)value);
    return rsp.value(v, true);
}

bool get_value(const Message& msg, const Environment& env, Response& rsp)
{
    uint32_t value;
    if (! value_store.get(test_key, value))
        return rsp.error("no such key");

    ww::value::Number v((double)value);
    return rsp.value(v, false);
}

contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(initialize),
    CONTRACT_METHOD(inc_value),
    CONTRACT_METHOD(get_value),
    { NULL, NULL }
};
