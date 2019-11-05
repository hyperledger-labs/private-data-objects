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

#pragma once

#include "Environment.h"
#include "Message.h"
#include "Response.h"

typedef bool (*contract_method_t)(const Message& m, const Environment& e, Response& r);

typedef struct
{
    const char* method_name;
    contract_method_t method_code;
} contract_method_reference_t;

extern bool initialize_contract(const Environment& env, Response& rsp);
extern contract_method_reference_t contract_method_dispatch_table[];

#define CONTRACT_METHOD(m) { #m, m }
