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

#include "Cryptography.h"
#include "Environment.h"
#include "KeyValue.h"
#include "Message.h"
#include "Response.h"
#include "StringArray.h"
#include "Util.h"
#include "Value.h"

#include "exchange_base.h"

static KeyValueStore exchange_base_store("exchange_base");

static const StringArray md_owner_key("owner");
static const StringArray md_initialized_key("initialized");

static const StringArray md_signing_key("ecdsa_private_key");
static const StringArray md_verifying_key("ecdsa_public_key");

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
bool ww::exchange::exchange_base::initialize_contract(
    const Environment& env,
    Response& rsp)
{
    // ---------- Mark as uninitialized ----------
    const int initialized = 0;
    if (! exchange_base_store.set(md_initialized_key, initialized))
        return rsp.error("failed to save initialization state");

    // ---------- Save owner information ----------
    const StringArray owner_val(env.creator_id_);
    if (! exchange_base_store.set(md_owner_key, owner_val))
        return rsp.error("failed to save creator metadata");

    // ---------- Create and save the ECDSA key pair ----------
    StringArray public_key;
    StringArray private_key;

    if (! ww::crypto::ecdsa::generate_keys(private_key, public_key))
        return rsp.error("failed to create contract ecdsa keys");

    if (! exchange_base_store.set(md_verifying_key, public_key))
        return rsp.error("failed to save ecdsa public key");

    if (! exchange_base_store.set(md_signing_key, private_key))
        return rsp.error("failed to save ecdsa private key");

    // ---------- RETURN ----------
    return rsp.success(true);
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
bool ww::exchange::exchange_base::get_verifying_key(
    const Message& msg,
    const Environment& env,
    Response& rsp)
{
    // NOTE: this method does not require initialization of the authority
    // object, that is "initialize_contract" must be called (but we couldn't
    // get here without that) but "initialize" method need not be called

    StringArray verifying_key;
    if (! ww::exchange::exchange_base::get_verifying_key(verifying_key))
        return rsp.error("corrupted state; verifying key not found");

    ww::value::String v((char*)verifying_key.c_data());
    return rsp.value(v, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// UTILITY FUNCTIONS
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
bool ww::exchange::exchange_base::get_verifying_key(StringArray& verifying_key)
{
    if (! exchange_base_store.get(md_verifying_key, verifying_key))
        return false;

    return true;
}

// -----------------------------------------------------------------
bool ww::exchange::exchange_base::get_signing_key(StringArray& signing_key)
{
    if (! exchange_base_store.get(md_signing_key, signing_key))
        return false;

    return true;
}

// -----------------------------------------------------------------
bool ww::exchange::exchange_base::mark_initialized(void)
{
    // Mark as initialized
    const uint32_t initialized = 1;
    if (! exchange_base_store.set(md_initialized_key, initialized))
        return false;

    return true;
}

// -----------------------------------------------------------------
bool ww::exchange::exchange_base::is_initialized(void)
{
    uint32_t initialized = 0;
    if (! exchange_base_store.get(md_initialized_key, initialized))
        return false;

    return (initialized == 1);
}
