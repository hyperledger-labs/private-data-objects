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

#include <stddef.h>
#include <stdint.h>

#include "Dispatch.h"

#include "Cryptography.h"
#include "Environment.h"
#include "KeyValue.h"
#include "Message.h"
#include "Response.h"
#include "Types.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "contract/base.h"

static KeyValueStore kv_test_store("kv_test_store");
const std::string test_key = "test_key";

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: initialize
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool initialize_contract(const Environment& env, Response& rsp)
{
    ASSERT_SUCCESS(rsp, ww::contract::base::initialize_contract(env),
                   "failed to initialize the base contract");

    ww::types::ByteArray initial_value;
    ASSERT_SUCCESS(rsp, ww::crypto::random_identifier(initial_value),
                   "failed to create the initial value");
    ASSERT_SUCCESS(rsp, kv_test_store.set(test_key, initial_value),
                   "failed to save the initial value");

    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// kv store test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define KV_SET_PARAMETER_SCHEMA                 \
    "{"                                         \
        SCHEMA_KW(encryption_key, "") ","       \
        SCHEMA_KW(state_hash, "") ","           \
        SCHEMA_KW(transfer_key, "")             \
    "}"

bool kv_set(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_CREATOR(env, rsp);
    ASSERT_SUCCESS(rsp, msg.validate_schema(KV_SET_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string encoded_encryption_key(msg.get_string("encryption_key"));
    const std::string encoded_state_hash(msg.get_string("state_hash"));
    const std::string transfer_key(msg.get_string("transfer_key"));

    ww::types::ByteArray encryption_key;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_decode(encoded_encryption_key, encryption_key),
                   "invalid encryption key");

    ww::types::ByteArray state_hash;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_decode(encoded_state_hash, state_hash),
                   "invalid state hash");

    int handle = KeyValueStore::open(state_hash, encryption_key);
    if (handle < 0)
        return rsp.error("failed to open the key value store");

    ww::types::ByteArray value;
    KeyValueStore input_store("", handle);

    ASSERT_SUCCESS(rsp, input_store.get(transfer_key, value),
                   "store does not contain a value");
    ASSERT_SUCCESS(rsp, kv_test_store.set(test_key, value),
                   "failed to save the new value");

    ww::types::ByteArray new_state_hash;
    ASSERT_SUCCESS(rsp, input_store.finalize(handle,new_state_hash),
                   "failed to close the output store");

    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// kv store test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define KV_GET_PARAMETER_SCHEMA                 \
    "{"                                         \
        SCHEMA_KW(encryption_key, "") ","       \
        SCHEMA_KW(state_hash, "") ","           \
        SCHEMA_KW(transfer_key, "")             \
    "}"
bool kv_get(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_CREATOR(env, rsp);
    ASSERT_SUCCESS(rsp, msg.validate_schema(KV_GET_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string encoded_encryption_key(msg.get_string("encryption_key"));
    const std::string encoded_state_hash(msg.get_string("state_hash"));
    const std::string transfer_key(msg.get_string("transfer_key"));

    ww::types::ByteArray encryption_key;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_decode(encoded_encryption_key, encryption_key),
                   "invalid encryption key");

    ww::types::ByteArray state_hash;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_decode(encoded_state_hash, state_hash),
                   "invalid state hash");

    int handle = KeyValueStore::open(state_hash, encryption_key);
    if (handle < 0)
        return rsp.error("failed to open the key value store");

    ww::types::ByteArray value;
    ASSERT_SUCCESS(rsp, kv_test_store.get(test_key, value),
                   "unexpected error: failed to get value");

    KeyValueStore output_store("", handle);
    ASSERT_SUCCESS(rsp, output_store.set(transfer_key, value),
                   "unexpected error: failed to save value");

    ww::types::ByteArray new_state_hash;
    ASSERT_SUCCESS(rsp, output_store.finalize(handle,new_state_hash),
                   "failed to close the output store");

    std::string encoded_new_state_hash;
    ASSERT_SUCCESS(rsp, ww::crypto::b64_encode(new_state_hash, encoded_new_state_hash),
                   "failed to encode state hash");

    ww::value::String result(encoded_new_state_hash.c_str());
    return rsp.value(result, false);
}


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(kv_get),
    CONTRACT_METHOD(kv_set),

    { NULL, NULL }
};
