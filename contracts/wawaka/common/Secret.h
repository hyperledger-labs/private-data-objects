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
#include <string>

#include "Util.h"
#include "Value.h"

#define CONTRACT_SECRET_SCHEMA                  \
    "{"                                         \
        SCHEMA_KW(encrypted_session_key,"") "," \
        SCHEMA_KW(session_key_iv,"") ","        \
        SCHEMA_KW(encrypted_message,"")         \
    "}"

namespace ww
{
namespace secret
{
    bool send_secret(
        const std::string& encryption_key,
        const std::string& message_string,
        std::string& encrypted_message_string);

    bool send_secret(
        const std::string& encryption_key,
        const std::string& message_string,
        ww::value::Object& secret_object);

    bool recv_secret(
        const std::string& decryption_key,
        const std::string& encrypted_message_string,
        std::string& message_string);

    bool recv_secret(
        const std::string& decryption_key,
        const ww::value::Object& secret_object,
        std::string& message_string);
};                              /* namespace secret */
};                              /* namespac ww */
