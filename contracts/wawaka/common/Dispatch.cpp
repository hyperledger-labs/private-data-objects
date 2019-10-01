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

#include "jsonvalue.h"
#include "parson.h"

#include <stdint.h>
#include <string.h>

#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "Dispatch.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static char *dispatch_wrapper(const char *message, const char *environment)
{
    Message msg;
    if (! msg.deserialize(message))
        return NULL;

    Environment env;
    if (! env.deserialize(environment))
        return NULL;

    Response rsp;

    const char* method_name = msg.get_string("method");
    if (method_name == NULL)
    {
        rsp.set_error_result("no function specified");
        return rsp.serialize();
    }

    // CONTRACT_SAFE_LOG(3, "method: %s", method_name);

    contract_method_reference_t* mptr = contract_method_dispatch_table;
    while (mptr->method_name)
    {
        if (strcmp(method_name, mptr->method_name) == 0)
        {
            (void) (*mptr->method_code)(msg, env, rsp);
            return rsp.serialize();
        }
        mptr++;
    }

    rsp.set_error_result(method_name);
    return rsp.serialize();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#ifdef __cplusplus
extern "C" {
#endif
char *dispatch(const char *message, const char *environment)
{
    return dispatch_wrapper(message, environment);
}

#ifdef __cplusplus
}
#endif
