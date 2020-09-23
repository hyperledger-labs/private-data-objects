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

#include <stddef.h>
#include <stdint.h>

#include "Dispatch.h"

#include "KeyValue.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "StringArray.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "exchange_base.h"

static KeyValueStore asset_type_store("asset_type_store");

const StringArray md_asset_type_id_key("asset_type_identifier");
const StringArray md_description_key("description");
const StringArray md_link_key("link");
const StringArray md_name_key("name");

// -----------------------------------------------------------------
// METHOD: initialize_contract
//   contract initialization method
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   true if successfully initialized
// -----------------------------------------------------------------
bool initialize_contract(const Environment& env, Response& rsp)
{
    CONTRACT_SAFE_LOG(4, "initialize_contract");

    if (! ww::exchange::exchange_base::initialize_contract(env, rsp))
        return false;

    // ---------- save the type identifier ----------
    const StringArray asset_type_identifier(env.contract_id_);
    if (! asset_type_store.set(md_asset_type_id_key, asset_type_identifier))
        return rsp.error("failed to save the asset type identifier");

    // ---------- RETURN ----------
    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: initialize
//   set the basic information for the asset type
//
// JSON PARAMETERS:
//   description -- string description of the type
//   link -- URL for more information
//   name -- short handle for the asset type
//
// RETURNS:
//   true if successfully initialized
// -----------------------------------------------------------------
bool initialize(const Message& msg, const Environment& env, Response& rsp)
{
    CONTRACT_SAFE_LOG(4, "initialize");

    ASSERT_SENDER_IS_OWNER(env, rsp);
    ASSERT_UNINITIALIZED(rsp);

    if (! msg.validate_schema("{\"description\":\"\", \"link\":\"\", \"name\":\"\"}"))
        return rsp.error("invalid request, missing required parameters");

    // save the description
    const StringArray description(msg.get_string("description"));
    if (! asset_type_store.set(md_description_key, description))
        return rsp.error("failed to store the description");

    // save the link
    const StringArray link(msg.get_string("link"));
    if (! asset_type_store.set(md_link_key, link))
        return rsp.error("failed to store the link");

    // save the name
    const StringArray name(msg.get_string("name"));

    if (! asset_type_store.set(md_name_key, name))
        return rsp.error("failed to store the name");

    // Mark as initialized
    if (! ww::exchange::exchange_base::mark_initialized())
        return rsp.error("failed to store the initialized flag");

    // ---------- RETURN ----------
    return rsp.success(true);
}

// -----------------------------------------------------------------
// METHOD: get_asset_type_identifier
//   set asset type identifier
//
// JSON PARAMETERS:
//   None
//
// RETURNS:
//   asset type identifier (the contract id)
// -----------------------------------------------------------------
bool get_asset_type_identifier(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    CONTRACT_SAFE_LOG(4, "get_identifier");

    StringArray asset_type_identifier;
    if (! asset_type_store.get(md_asset_type_id_key, asset_type_identifier))
        return rsp.error("contract state corrupted, no asset type identifier");

    ww::value::String v((char*)asset_type_identifier.c_data());
    return rsp.value(v, false);
}

// -----------------------------------------------------------------
// METHOD: get_description
//   set asset type description
//
// JSON PARAMETERS:
//   None
//
// RETURNS:
//   asset type description
// -----------------------------------------------------------------
bool get_description(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    CONTRACT_SAFE_LOG(4, "get_description");

    StringArray description;
    if (! asset_type_store.get(md_description_key, description))
        return rsp.error("contract state corrupted, no description");

    ww::value::String v((char*)description.c_data());
    return rsp.value(v, false);
}

// -----------------------------------------------------------------
// METHOD: get_link
//   set asset type link
//
// JSON PARAMETERS:
//   None
//
// RETURNS:
//   asset type link
// -----------------------------------------------------------------
bool get_link(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    CONTRACT_SAFE_LOG(4, "get_link");

    StringArray link;
    if (! asset_type_store.get(md_link_key, link))
        return rsp.error("contract state corrupted, no link");

    ww::value::String v((char*)link.c_data());
    return rsp.value(v, false);
}

// -----------------------------------------------------------------
// METHOD: get_name
//   set asset type name
//
// JSON PARAMETERS:
//   None
//
// RETURNS:
//   asset type name
// -----------------------------------------------------------------
bool get_name(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    CONTRACT_SAFE_LOG(4, "get_name");

    StringArray name;
    if (! asset_type_store.get(md_name_key, name))
        return rsp.error("contract state corrupted, no name");

    ww::value::String v((char*)name.c_data());
    return rsp.value(v, false);
}

// -----------------------------------------------------------------
// -----------------------------------------------------------------
contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(initialize),
    CONTRACT_METHOD(get_asset_type_identifier),
    CONTRACT_METHOD(get_description),
    CONTRACT_METHOD(get_link),
    CONTRACT_METHOD(get_name),
    { NULL, NULL }
};
