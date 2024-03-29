/* Copyright 2020 Intel Corporation
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

#include "Types.h"
#include "Dispatch.h"

#include "KeyValue.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Value.h"
#include "WasmExtensions.h"

static KeyValueStore meta_store("meta");

const std::string owner_key("owner");
const std::string default_key("key");

const uint32_t default_value_32 = 13;
const uint8_t default_value_8 = 13;

// -----------------------------------------------------------------
// NAME: initialize_contract
// -----------------------------------------------------------------
bool initialize_contract(const Environment& env, Response& rsp)
{
    // save owner information
    const ww::types::ByteArray owner_val(env.creator_id_.begin(), env.creator_id_.end());

    if (! meta_store.set(owner_key, owner_val))
        return rsp.error("failed to save creator metadata");

    return rsp.success(true);
}

// -----------------------------------------------------------------
// NAME: many_keys_test
// -----------------------------------------------------------------
bool many_keys_test(const Message& msg, const Environment& env, Response& rsp)
{
    int num_keys((int)msg.get_number("num_keys"));

    int i = 0;
    for (i = 0; i < num_keys; i++) {
        ww::types::ByteArray key(12);
        sprintf((char *)key.data(), "%d", i);
        if (! meta_store.set(key, default_value_32))
            return rsp.error("failed to store value");
    }

    ww::value::Number v((double)i);
    return rsp.value(v, true);
}

// -----------------------------------------------------------------
// NAME: big_key_test
// -----------------------------------------------------------------
bool big_key_test(const Message& msg, const Environment& env, Response& rsp)
{
    int num_chars((int)msg.get_number("num_chars"));
    ww::types::ByteArray key(num_chars, default_value_8);

    if (!meta_store.set(key, default_value_32))
        return rsp.error("failed to store value");

    ww::value::Number v((double)key.size());
    return rsp.value(v, true);
}

// -----------------------------------------------------------------
// NAME: big_value_test
// -----------------------------------------------------------------
bool big_value_test(const Message& msg, const Environment& env, Response& rsp)
{
    int num_chars((int)msg.get_number("num_chars"));
    ww::types::ByteArray value(num_chars, default_value_8);

    if (!meta_store.set(default_key, value))
        return rsp.error("failed to store value");

    ww::value::Number v((double)value.size());
    return rsp.value(v, true);
}

// -----------------------------------------------------------------
// NAME: many_kv_pair_test
// -----------------------------------------------------------------
bool many_kv_pairs_test(const Message& msg, const Environment& env, Response& rsp)
{
    int num_chars((int)msg.get_number("num_chars"));
    int num_keys((int)msg.get_number("num_keys"));

    int i = 0;
    ww::types::ByteArray value(num_chars, default_value_8);

    for (i = 0; i < num_keys; i++) {
        ww::types::ByteArray key(12);
        sprintf((char *)key.data(), "%d", i);
        if (!meta_store.set(key, value))
            return rsp.error("failed to store value");
    }

    ww::value::Number v((double)(i*value.size()));
    return rsp.value(v, true);
}

static int simple_recursive_function(int n) {
    if (n > 0) {
        return simple_recursive_function(n-1) + 1;
    }
    return 0;
}

bool deep_recursion_test(const Message& msg, const Environment& env, Response& rsp) {

    int levels((int)msg.get_number("levels"));
    if (levels < 0) {
        return rsp.error("need positive int for recursion depth");
    }

    int depth = simple_recursive_function(levels);

    ww::value::Number v((double)depth);
    return rsp.value(v, false);
}

contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(many_keys_test),
    CONTRACT_METHOD(big_key_test),
    CONTRACT_METHOD(big_value_test),
    CONTRACT_METHOD(many_kv_pairs_test),
    CONTRACT_METHOD(deep_recursion_test),
    { NULL, NULL }
};
