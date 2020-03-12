/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>

#include "bh_platform.h"
#include "wasm_export.h"
#include "lib_export.h"

#include "basic_kv.h"
#include "error.h"
#include "log.h"
#include "pdo_error.h"
#include "types.h"

//#include <stddef.h>   /* size_t */
#include <string.h>
#include <ctype.h>
#include <math.h>

#include "WasmCryptoExtensions.h"
#include "WasmStateExtensions.h"
#include "WasmUtil.h"

namespace pe = pdo::error;

/* ----------------------------------------------------------------- *
 * NAME: memchr
 * ----------------------------------------------------------------- */
extern "C" int32 memchr_wrapper(
    wasm_exec_env_t exec_env,
    int32 src_offset,
    int32 ch,
    uint32 src_size)
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        if (src_size == 0)
            return 0;

        void *src = get_buffer(module_inst, src_offset, src_size);
        if (src == NULL)
            return 0;

        void *ptr = memchr(src, ch, src_size);
        if (ptr == NULL)
            return 0;

        return wasm_runtime_addr_native_to_app(module_inst, ptr);
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: _contract_log_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool contract_log_wrapper(
    wasm_exec_env_t exec_env,
    const int32 loglevel,
    const char* buffer)
{
    // wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        SAFE_LOG(loglevel, "CONTRACT: %s", buffer);
        return true;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: simple_hash
 * ----------------------------------------------------------------- */
extern "C" int simple_hash_wrapper(
    wasm_exec_env_t exec_env,
    uint8_t* buffer,
    const int buffer_length)
{
    // wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        if (buffer == NULL)
            return -1;

        unsigned int result = 0;
        for (int i = 0; i < buffer_length; i++, buffer++)
        {
            int temp;
            temp = (result << 6) + (result << 16) - result;
            result = (*buffer) + temp;
        }

        return result;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return -1;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: strtod
 * ----------------------------------------------------------------- */
extern "C" double strtod_wrapper(
    wasm_exec_env_t exec_env,
    const char *nptr,
    char **endptr)
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    double num = 0;

    if (! wasm_runtime_validate_native_addr(module_inst, endptr, sizeof(uint32)))
        return 0;

    num = strtod(nptr, endptr);
    *(int32*)endptr = wasm_runtime_addr_native_to_app(module_inst, *endptr);

    return num;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#ifdef __cplusplus
extern "C" {
#endif

#define WASM_PASSTHRU_FUNCTION(function) \
    static int function##_wrapper(wasm_module_inst_t m, int c) { return function(c); }

WASM_PASSTHRU_FUNCTION(iscntrl)
WASM_PASSTHRU_FUNCTION(islower)
WASM_PASSTHRU_FUNCTION(ispunct)
WASM_PASSTHRU_FUNCTION(isblank)

#if 0
WASM_PASSTHRU_FUNCTION(isascii)
#endif

static NativeSymbol native_symbols[] =
{
    /* Missing libc functions */
    EXPORT_WASM_API_WITH_SIG2(iscntrl,"(i)i"),
    EXPORT_WASM_API_WITH_SIG2(islower,"(i)i"),
    EXPORT_WASM_API_WITH_SIG2(ispunct,"(i)i"),
    EXPORT_WASM_API_WITH_SIG2(isblank,"(i)i"),
#if 0
    EXPORT_WASM_API_WITH_SIG2(isascii,"(i)i"),
#endif

    /* Crypto operations from WasmCryptoExtensions.h */
    EXPORT_WASM_API_WITH_SIG2(b64_encode,"(iiii)i"),
    EXPORT_WASM_API_WITH_SIG2(b64_decode,"(iiii)i"),
    EXPORT_WASM_API_WITH_SIG2(ecdsa_create_signing_keys,"(iiii)i"),
    EXPORT_WASM_API_WITH_SIG2(ecdsa_sign_message,"(iiiiii)i"),
    EXPORT_WASM_API_WITH_SIG2(ecdsa_verify_signature,"(iiiiii)i"),
    EXPORT_WASM_API_WITH_SIG2(aes_generate_key,"(ii)i"),
    EXPORT_WASM_API_WITH_SIG2(aes_generate_iv,"(iiii)i"),
    EXPORT_WASM_API_WITH_SIG2(aes_encrypt_message,"(iiiiiiii)i"),
    EXPORT_WASM_API_WITH_SIG2(aes_decrypt_message,"(iiiiiiii)i"),
    EXPORT_WASM_API_WITH_SIG2(rsa_generate_keys,"(iiii)i"),
    EXPORT_WASM_API_WITH_SIG2(rsa_encrypt_message,"(iiiiii)i"),
    EXPORT_WASM_API_WITH_SIG2(rsa_decrypt_message,"(iiiiii)i"),
    EXPORT_WASM_API_WITH_SIG2(crypto_hash,"(iiii)i"),
    EXPORT_WASM_API_WITH_SIG2(random_identifier,"(ii)i"),

    /* Persistent store operations from WasmStateExtensions.h */
    EXPORT_WASM_API_WITH_SIG2(key_value_set,"(*~*~)i"),
    EXPORT_WASM_API_WITH_SIG2(key_value_get,"(*~ii)i"),

    /* Utility functions */
    EXPORT_WASM_API_WITH_SIG2(contract_log, "(i$)i"),
    EXPORT_WASM_API_WITH_SIG2(simple_hash, "(*~)i"),
    EXPORT_WASM_API_WITH_SIG2(memchr, "(iii)i"),
    EXPORT_WASM_API_WITH_SIG2(strtod, "($*)F"),
};

#ifdef __cplusplus
}
#endif

bool RegisterNativeFunctions(void)
{
    try {
        size_t native_symbols_count = sizeof(native_symbols)/sizeof(NativeSymbol);
        if (! wasm_runtime_register_natives("env", native_symbols, native_symbols_count))
        {
            SAFE_LOG(PDO_LOG_ERROR, "failed to register native functions");
            return false;
        }
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "exception throw while registering native functions");
        return false;
    }

    return true;
}

//#include "ext_lib_export.h"
