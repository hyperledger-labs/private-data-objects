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

#include <string>

#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Types.h"
#include "Util.h"

#define LEDGER_ATTESTATION_SCHEMA               \
    "{"                                         \
        SCHEMA_KW(contract_code_hash,"") ","    \
        SCHEMA_KW(metadata_hash,"") ","         \
        SCHEMA_KW(signature,"")                 \
    "}"

#define CONTRACT_METADATA_SCHEMA                \
    "{"                                         \
        SCHEMA_KW(verifying_key,"") ","         \
        SCHEMA_KW(encryption_key,"")            \
    "}"

#define CONTRACT_CODE_METADATA_SCHEMA           \
    "{"                                         \
        SCHEMA_KW(code_hash,"") ","             \
        SCHEMA_KW(code_nonce,"")                \
    "}"

#define SET_LEDGER_KEY_PARAM_SCHEMA             \
    "{"                                         \
        SCHEMA_KW(ledger_verifying_key,"")      \
    "}"

#define ADD_ENDPOINT_PARAM_SCHEMA                                       \
     "{"                                                                \
         SCHEMA_KW(contract_id,"") ","                                  \
         SCHEMA_KWS(ledger_attestation, LEDGER_ATTESTATION_SCHEMA) ","  \
         SCHEMA_KWS(contract_metadata, CONTRACT_METADATA_SCHEMA) ","    \
         SCHEMA_KWS(contract_code_metadata, CONTRACT_CODE_METADATA_SCHEMA) \
     "}"

namespace ww
{
namespace contract
{
namespace attestation
{
    // this module defines several contract methods and associated utility functions
    // that are shared between asset contracts, specifically, the methods create
    // an ecdsa key pair

    // common function to initialize state for issuer authority use
    bool initialize_contract(const Environment& env);

    // common contract methods
    bool set_ledger_key(const Message& msg, const Environment& env, Response& rsp);
    bool get_ledger_key(const Message& msg, const Environment& env, Response& rsp);
    bool get_contract_metadata(const Message& msg, const Environment& env, Response& rsp);
    bool get_contract_code_metadata(const Message& msg, const Environment& env, Response& rsp);
    bool add_endpoint(const Message& msg, const Environment& env, Response& rsp);

    // utility functions
    bool set_ledger_key(const std::string& ledger_verifying_key);
    bool get_ledger_key(std::string& ledger_verifying_key);

    bool compute_code_hash(ww::types::ByteArray& code_hash);
    bool set_code_hash(const ww::types::ByteArray& code_hash);
    bool get_code_hash(ww::types::ByteArray& code_hash);

    bool add_endpoint(const std::string& contract_id, const std::string& verifying_key, const std::string& encryption_key);
    bool get_endpoint(const std::string& contract_id, std::string& verifying_key, std::string& encryption_key);
}; // attestation
}; // contract
}; // ww
