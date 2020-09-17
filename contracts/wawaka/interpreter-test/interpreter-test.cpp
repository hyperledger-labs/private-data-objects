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

#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "Dispatch.h"

#include "Cryptography.h"
#include "Environment.h"
#include "KeyValue.h"
#include "Message.h"
#include "Response.h"
#include "StringArray.h"
#include "Value.h"
//#include "WasmExtensions.h"

static KeyValueStore meta_store("meta");
static KeyValueStore value_store("values");
static KeyValueStore owner_store("owners");

const StringArray owner_key("owner");
const StringArray signing_key("ecdsa-private-key");
const StringArray verifying_key("ecdsa-public-key");
const StringArray symmetric_key("aes-encryption-key");
const StringArray public_encrypt_key("rsa-public-key");
const StringArray private_decrypt_key("rsa-private-key");

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: initialize
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool initialize_contract(const Environment& env, Response& rsp)
{
    // ---------- Save owner information ----------
    const StringArray owner_val(env.creator_id_);

    if (! meta_store.set(owner_key, owner_val))
        return rsp.error("failed to save creator metadata");

    // ---------- Create and save the ECDSA key pair ----------
    StringArray public_key;
    StringArray private_key;

    if (! ww::crypto::ecdsa::generate_keys(private_key, public_key))
        return rsp.error("failed to create contract ecdsa keys");

    if (! meta_store.set(verifying_key, public_key))
        return rsp.error("failed to save ecdsa public key");

    if (! meta_store.set(signing_key, private_key))
        return rsp.error("failed to save ecdsa private key");

    // ---------- Create and save the AES key ----------
    StringArray aes_key;

    if (! ww::crypto::aes::generate_key(aes_key))
        return rsp.error("failed to create the AES key");

    if (! meta_store.set(symmetric_key, aes_key))
        return rsp.error("failed to save the AES key");

    // ---------- Create and save the RSA key pair ----------
    StringArray rsa_private_key;
    StringArray rsa_public_key;

    if (! ww::crypto::rsa::generate_keys(rsa_private_key, rsa_public_key))
        return rsp.error("failed to create rsa keys");

    if (! meta_store.set(public_encrypt_key, rsa_public_key))
        return rsp.error("failed to save rsa public key");

    if (! meta_store.set(private_decrypt_key, rsa_private_key))
        return rsp.error("failed to save rsa private key");

    // ---------- Create the return value ----------
    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: ecdsa_test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ecdsa_test(const Message& msg, const Environment& env, Response& rsp)
{
    const StringArray message(msg.get_string("message"));

    // ---------- get the keys we need ----------
    StringArray private_key;
    if (! meta_store.get(signing_key, private_key))
        return rsp.error("failed to find private key");

    StringArray public_key;
    if (! meta_store.get(verifying_key, public_key))
        return rsp.error("failed to find public key");

    // ---------- sign the message ----------
    StringArray signature;
    if (! ww::crypto::ecdsa::sign_message(message, private_key, signature))
        return rsp.error("failed to sign message");

    if (! ww::crypto::ecdsa::verify_signature(message, public_key, signature))
        return rsp.error("failed to verify the signature");

    // ---------- return the signature ----------
    StringArray encoded;
    if (! ww::crypto::b64_encode(signature, encoded))
        return rsp.error("failed to encode signature");

    ww::value::String v((char*)encoded.c_data());
    return rsp.value(v, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: aes_test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool aes_test(const Message& msg, const Environment& env, Response& rsp)
{
    const StringArray message(msg.get_string("message"));

    // ---------- get the keys we need ----------
    StringArray key;
    if (! meta_store.get(symmetric_key, key))
        return rsp.error("failed to find private key");

    StringArray iv;
    if (! ww::crypto::aes::generate_iv(iv))
        return rsp.error("failed to generate iv");

    // ---------- encrypt the message ----------
    StringArray cipher;
    if (! ww::crypto::aes::encrypt_message(message, key, iv, cipher))
        return rsp.error("failed to encrypt the message");

    // ---------- decrypt the message ----------
    StringArray newmessage;
    if (! ww::crypto::aes::decrypt_message(cipher, key, iv, newmessage))
        return rsp.error("failed to decrypt the message");

    if (! message.equal(newmessage))
        return rsp.error("decrypted message differs from original message");

    // ---------- return the signature ----------
    StringArray encoded;
    if (! ww::crypto::b64_encode(cipher, encoded))
        return rsp.error("failed to encode cipher text");

    ww::value::String v((char*)encoded.c_data());
    return rsp.value(v, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: rsa_test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool rsa_test(const Message& msg, const Environment& env, Response& rsp)
{
    // ---------- get the keys we need ----------
    StringArray rsa_public;
    if (! meta_store.get(public_encrypt_key, rsa_public))
        return rsp.error("failed to find rsa public key");

    StringArray rsa_private;
    if (! meta_store.get(private_decrypt_key, rsa_private))
        return rsp.error("failed to find rsa private key");

    StringArray aes_key;
    if (! meta_store.get(symmetric_key, aes_key))
        return rsp.error("failed to find aes key");

    // ---------- encrypt the aes key ----------
    StringArray cipher;
    if (! ww::crypto::rsa::encrypt_message(aes_key, rsa_public, cipher))
        return rsp.error("failed to encrypt the key");

    // ---------- decrypt the message ----------
    StringArray new_aes_key;
    if (! ww::crypto::rsa::decrypt_message(cipher, rsa_private, new_aes_key))
        return rsp.error("failed to decrypt the key");

    if (! aes_key.equal(new_aes_key))
        return rsp.error("decrypted key differs from the original key");

    // ---------- return the signature ----------
    StringArray encoded;
    if (! ww::crypto::b64_encode(cipher, encoded))
        return rsp.error("failed to encode cipher text");

    ww::value::String v((char*)encoded.c_data());
    return rsp.value(v, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(ecdsa_test),
    CONTRACT_METHOD(aes_test),
    CONTRACT_METHOD(rsa_test),
    { NULL, NULL }
};
