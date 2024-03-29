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

#include <stdint.h>

#include "Types.h"

#define SCHEMA_KW(kw,v) "\"" #kw "\":" #v
#define SCHEMA_KWS(kw, s) "\"" #kw "\":" s

#define ASSERT_SUCCESS(_rsp_, _condition_, _message_)   \
    do {                                                \
        if (! ( _condition_) ) {                        \
            return _rsp_.error(_message_);              \
        }                                               \
    } while (0)

#define ASSERT_SENDER_IS_CREATOR(_env, _rsp)                            \
    do {                                                                \
        if (_env.creator_id_ != _env.originator_id_)                    \
            return _rsp.error("only the owner may invoke this method"); \
    } while (0)

// set to 0 for more memory efficient implementation
#define SAFE_INTERNAL_COPY

bool copy_internal_pointer(
    ww::types::ByteArray& result,
    const uint8_t* pointer,
    const uint32_t size);
