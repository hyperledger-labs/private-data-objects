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
    //CONTRACT_SAFE_LOG(3, "dispatch_wrapper");

    Message msg;
    if (! msg.deserialize(message))
        return NULL;

    Environment env;
    if (! env.deserialize(environment))
        return NULL;

    Response rsp;

    const char* method_name = msg.get_string("Method");
    if (method_name == NULL)
    {
        rsp.error("no function specified");
        return rsp.serialize();
    }

    ww::value::Object kparams;
    if (! msg.get_value("KeywordParameters", kparams))
    {
        rsp.error("missing required parameter, KeywordParameters");
        return rsp.serialize();
    }

    ww::value::Array pparams;
    if (! msg.get_value("PositionalParameters", pparams))
    {
        rsp.error("missing required parameter, PositionalParameters");
        return rsp.serialize();
    }

    //CONTRACT_SAFE_LOG(3, "method: %s", method_name);

    contract_method_reference_t* mptr = contract_method_dispatch_table;
    while (mptr->method_name)
    {
        if (strcmp(method_name, mptr->method_name) == 0)
        {
            (void) (*mptr->method_code)(kparams, env, rsp);
            return rsp.serialize();
        }
        mptr++;
    }

    rsp.error(method_name);
    return rsp.serialize();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static char *initialize_wrapper(const char *environment)
{
    //CONTRACT_SAFE_LOG(3, "initialize_wrapper");

    Environment env;
    if (! env.deserialize(environment))
        return NULL;

    Response rsp;

    initialize_contract(env, rsp);
    return rsp.serialize();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#ifdef __cplusplus
extern "C" {
#endif
extern void __wasm_call_ctors(void);

// for each of these, we should call both the ctors and
// dtors functions. and that would probably mean making
// sure that we handle atexit correctly. the lack of global
// destructors could become a problem if we attempt to re-use
// an instantiated wamr module or if someone decides to put
// semantically interesting computation in the destructor of
// a global variable (which seems like an incredibly bad idea)

char *ww_dispatch(const char *message, const char *environment)
{
    __wasm_call_ctors();
    return dispatch_wrapper(message, environment);
}

char *ww_initialize(const char *environment)
{
    __wasm_call_ctors();
    return initialize_wrapper(environment);
}

#ifdef USE_WASI_SDK
// -----------------------------------------------------------------
// these helper functions are necessary to initialize the WASM environment
// when using the wasi-sdk toolchain
// -----------------------------------------------------------------
int __cxa_atexit(void (*f)(void *), void *p, void *d) { return 0; }
void _start(void) {}
#endif

#ifdef __cplusplus
}
#endif
