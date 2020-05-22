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

#include "Dispatch.h"

#include "KeyValue.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "StringArray.h"
#include "Value.h"
#include "WasmExtensions.h"

// -----------------------------------------------------------------
// NAME: initialize_contract
// -----------------------------------------------------------------
bool initialize_contract(const Environment& env, Response& rsp)
{
    return rsp.success(false);
}

// Recursively compute the n-th fibonacci number
static uint32_t compute_fib(uint32_t n)
{
    if (n <= 1)
        return n;
    return compute_fib(n-1)+compute_fib(n-2);
}

// -----------------------------------------------------------------
// NAME: fibonacci
// -----------------------------------------------------------------
bool fibonacci(const Message& msg, const Environment& env, Response& rsp)
{
    uint32_t n = (uint32_t)msg.get_number("message");
    uint32_t fib = compute_fib(n);

    ww::value::Number v((double)fib);
    return rsp.value(v, false);
}

contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(fibonacci),
    { NULL, NULL }
};
