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
#include "StringArray.h"

#include "common/IssuerAuthorityChain.h"

namespace ww
{
namespace exchange
{
namespace issuer_authority_base
{
    // this module defines several contract methods that are shared between the issuer
    // authorities which include issuers and vetting organizations

    // contract methods
    bool initialize_root_authority(const Message& msg, const Environment& env, Response& rsp);
    bool initialize_derived_authority(const Message& msg, const Environment& env, Response& rsp);

    bool get_asset_type_identifier(const Message& msg, const Environment& env, Response& rsp);
    bool get_authority(const Message& msg, const Environment& env, Response& rsp);
    bool add_approved_issuer(const Message& msg, const Environment& env, Response& rsp);
    bool get_issuer_authority(const Message& msg, const Environment& env, Response& rsp);

    // utility functions
    bool get_asset_type_identifier(StringArray& asset_type_identifier);
    bool get_authority(ww::exchange::IssuerAuthorityChain& authority_chain);

}; // issuer_authority
}; // exchange
}; // ww
