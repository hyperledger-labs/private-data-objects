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
#include "Types.h"

#include "Cryptography.h"
#include "Environment.h"
#include "KeyValue.h"
#include "Message.h"
#include "Response.h"
#include "Types.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "contract/base.h"

static KeyValueStore contract_base_store("contract_base");

static const std::string md_owner_key("owner");
static const std::string md_initialized_key("initialized");

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// CONTRACT METHODS
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
// METHOD: initialize_contract
//   contract initialization function, this is not a method but rather
//   the function called when the contract object is first initialized,
//   creates an ecdsa key pair that can be used to sign messages from
//   the contract
//
// JSON PARAMETERS:
//   none
//
// ENVIRONMENT:
//   creator_id_
//
// RETURNS:
//   true if successfully initialized
// -----------------------------------------------------------------
bool ww::contract::base::initialize_contract(const Environment& env)
{
    // ---------- Mark as uninitialized ----------
    const int initialized = 0;
    if (! contract_base_store.set(md_initialized_key, initialized))
    {
        CONTRACT_SAFE_LOG(3, "failed to save initialization state");
        return false;
    }

    // ---------- Save owner information ----------
    if (! set_owner(env.creator_id_))
    {
        CONTRACT_SAFE_LOG(3, "failed to save creator metadata");
        return false;
    }

    // ---------- RETURN ----------
    return true;
}

// -----------------------------------------------------------------
// METHOD: get_verifying_key
//   contract method to retrieve the ecdsa verifying key that was
//   created during initialization
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   ecdsa verifying key
// -----------------------------------------------------------------
bool ww::contract::base::get_verifying_key(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    std::string verifying_key;
    if (! ww::contract::base::get_verifying_key(verifying_key))
        return rsp.error("corrupted state; verifying key not found");

    ww::value::String v(verifying_key.c_str());
    return rsp.value(v, false);
}

// -----------------------------------------------------------------
// METHOD: get_encryption_key
//   contract method to retrieve the rsa encryption key that was
//   created during initialization
//
// JSON PARAMETERS:
//   none
//
// RETURNS:
//   rsa encryption key
// -----------------------------------------------------------------
bool ww::contract::base::get_encryption_key(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    std::string encryption_key;
    if (! ww::contract::base::get_encryption_key(encryption_key))
        return rsp.error("corrupted state; encryption key not found");

    ww::value::String v(encryption_key.c_str());
    return rsp.value(v, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// UTILITY FUNCTIONS
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
bool ww::contract::base::get_verifying_key(std::string& verifying_key)
{
    if (! KeyValueStore::privileged_get("ContractKeys.Verifying", verifying_key))
    {
        CONTRACT_SAFE_LOG(3, "failed to retreive privileged value for ContractKeys.Verifying");
        return false;
    }

    return true;
}

// -----------------------------------------------------------------
bool ww::contract::base::get_signing_key(std::string& signing_key)
{
    if (! KeyValueStore::privileged_get("ContractKeys.Signing", signing_key))
    {
        CONTRACT_SAFE_LOG(3, "failed to retreive privileged value for ContractKeys.Signing");
        return false;
    }

    return true;
}

// -----------------------------------------------------------------
bool ww::contract::base::get_encryption_key(std::string& encryption_key)
{
    if (! KeyValueStore::privileged_get("ContractKeys.Encryption", encryption_key))
    {
        CONTRACT_SAFE_LOG(3, "failed to retreive privileged value for ContractKeys.Encryption");
        return false;
    }

    return true;
}

// -----------------------------------------------------------------
bool ww::contract::base::get_decryption_key(std::string& decryption_key)
{
    if (! KeyValueStore::privileged_get("ContractKeys.Decryption", decryption_key))
    {
        CONTRACT_SAFE_LOG(3, "failed to retreive privileged value for ContractKeys.Decryption");
        return false;
    }

    return true;
}

// -----------------------------------------------------------------
bool ww::contract::base::mark_initialized(void)
{
    // Mark as initialized
    const uint32_t initialized = 1;
    if (! contract_base_store.set(md_initialized_key, initialized))
        return false;

    return true;
}

// -----------------------------------------------------------------
bool ww::contract::base::is_initialized(void)
{
    uint32_t initialized = 0;
    if (! contract_base_store.get(md_initialized_key, initialized))
        return false;

    return (initialized == 1);
}

// -----------------------------------------------------------------
bool ww::contract::base::set_owner(const std::string& owner)
{
    return contract_base_store.set(md_owner_key, owner);
}

// -----------------------------------------------------------------
bool ww::contract::base::get_owner(std::string& owner)
{
    return contract_base_store.get(md_owner_key, owner);
}
