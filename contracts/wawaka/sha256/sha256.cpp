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
#include <stdio.h>
#include <string>

#include "Dispatch.h"

#include "sha2.h"

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
// NAME: sha256_test
// Used for performance testing
// -----------------------------------------------------------------
bool sha256_test(const Message& msg, const Environment& env, Response& rsp)
{
    int num_chars((int)msg.get_number("num_chars"));

    StringArray message(num_chars);
    for (int i = 0; i < num_chars; i++) {
        message.set('a', i);
    }

    StringArray digest(SHA256_DIGEST_SIZE);
    sha256(message.c_data(), message.size(), digest.value_);

    return rsp.success(false);
}

// -----------------------------------------------------------------
// NAME: sha256_digest
// -----------------------------------------------------------------
bool sha256_digest(const Message& msg, const Environment& env, Response& rsp)
{
    StringArray message(msg.get_string("message"));

    StringArray digest(SHA256_DIGEST_SIZE);
    sha256(message.c_data(), message.size(), digest.value_);

    StringArray encoded;
    if (!b64_encode(digest.value_, digest.size_, (char**)&encoded.value_, &encoded.size_))
        return rsp.error("failed to encode sha256 hash");

    ww::value::String v((char *)encoded.value_);
    return rsp.value(v, false);
}

contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(sha256_digest),
    CONTRACT_METHOD(sha256_test),
    { NULL, NULL }
};
