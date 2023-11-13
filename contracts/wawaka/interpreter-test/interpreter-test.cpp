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

#include "Types.h"
#include "Dispatch.h"

#include "Cryptography.h"
#include "Environment.h"
#include "KeyValue.h"
#include "Message.h"
#include "Response.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

static KeyValueStore meta_store("meta");
static KeyValueStore value_store("values");
static KeyValueStore owner_store("owners");

const std::string owner_key("owner");
const std::string signing_key("ecdsa-private-key");
const std::string verifying_key("ecdsa-public-key");
const std::string symmetric_key("aes-encryption-key");
const std::string public_encrypt_key("rsa-public-key");
const std::string private_decrypt_key("rsa-private-key");

const std::string kv_test_key("test");
const std::string kv_hash_id("kv-store-hash-id");

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: initialize
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool initialize_contract(const Environment& env, Response& rsp)
{
    // ---------- Save owner information ----------
    const ww::types::ByteArray owner_val(env.creator_id_.begin(), env.creator_id_.end());

    if (! meta_store.set(owner_key, owner_val))
        return rsp.error("failed to save creator metadata");

    // ---------- Create and save the ECDSA key pair ----------
    std::string public_key;
    std::string private_key;

    if (! ww::crypto::ecdsa::generate_keys(private_key, public_key))
        return rsp.error("failed to create contract ecdsa keys");

    if (! meta_store.set(verifying_key, public_key))
        return rsp.error("failed to save ecdsa public key");

    if (! meta_store.set(signing_key, private_key))
        return rsp.error("failed to save ecdsa private key");

    // ---------- Create and save the AES key ----------
    ww::types::ByteArray aes_key;

    if (! ww::crypto::aes::generate_key(aes_key))
        return rsp.error("failed to create the AES key");

    if (! meta_store.set(symmetric_key, aes_key))
        return rsp.error("failed to save the AES key");

    // ---------- Create and save the RSA key pair ----------
    std::string rsa_private_key;
    std::string rsa_public_key;

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
    const std::string message_string(msg.get_string("message"));
    const ww::types::ByteArray message(message_string.begin(), message_string.end());

    // ---------- get the keys we need ----------
    std::string private_key;
    if (! meta_store.get(signing_key, private_key))
        return rsp.error("failed to find private key");

    std::string public_key;
    if (! meta_store.get(verifying_key, public_key))
        return rsp.error("failed to find public key");

    // ---------- sign the message ----------
    ww::types::ByteArray signature;
    if (! ww::crypto::ecdsa::sign_message(message, private_key, signature))
        return rsp.error("failed to sign message");

    if (! ww::crypto::ecdsa::verify_signature(message, public_key, signature))
        return rsp.error("failed to verify the signature");

    // ---------- return the signature ----------
    std::string encoded;
    if (! ww::crypto::b64_encode(signature, encoded))
        return rsp.error("failed to encode signature");

    ww::value::String v(encoded.c_str());
    return rsp.value(v, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: extended_ecdsa_test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool extended_ecdsa_test(const Message& msg, const Environment& env, Response& rsp)
{
    const std::string message_string(msg.get_string("message"));
    const ww::types::ByteArray message(message_string.begin(), message_string.end());

    // ---------- get the keys we need ----------
    ww::types::ByteArray bytes(48);
    ASSERT_SUCCESS(
        rsp, ww::crypto::random_identifier(bytes),
        "failed to build random identifier");

    std::string private_key;
    std::string public_key;

    ASSERT_SUCCESS(
        rsp, ww::crypto::ecdsa::generate_keys(bytes, private_key, public_key),
        "failed to generate ecdsa key from extended value");

    // ---------- sign the message ----------
    ww::types::ByteArray signature;
    if (! ww::crypto::ecdsa::sign_message(message, private_key, signature))
        return rsp.error("failed to sign message");

    if (! ww::crypto::ecdsa::verify_signature(message, public_key, signature))
        return rsp.error("failed to verify the signature");

    // ---------- return the signature ----------
    std::string encoded;
    if (! ww::crypto::b64_encode(signature, encoded))
        return rsp.error("failed to encode signature");

    ww::value::String v(encoded.c_str());
    return rsp.value(v, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: aes_test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool aes_test(const Message& msg, const Environment& env, Response& rsp)
{
    const std::string message_string(msg.get_string("message"));
    const ww::types::ByteArray message(message_string.begin(), message_string.end());

    // ---------- get the keys we need ----------
    ww::types::ByteArray key;
    if (! meta_store.get(symmetric_key, key))
        return rsp.error("failed to find private key");

    ww::types::ByteArray iv;
    if (! ww::crypto::aes::generate_iv(iv))
        return rsp.error("failed to generate iv");

    // ---------- encrypt the message ----------
    ww::types::ByteArray cipher;
    if (! ww::crypto::aes::encrypt_message(message, key, iv, cipher))
        return rsp.error("failed to encrypt the message");

    // ---------- decrypt the message ----------
    ww::types::ByteArray newmessage;
    if (! ww::crypto::aes::decrypt_message(cipher, key, iv, newmessage))
        return rsp.error("failed to decrypt the message");

    if (message != newmessage)
        return rsp.error("decrypted message differs from original message");

    // ---------- return the signature ----------
    std::string encoded;
    if (! ww::crypto::b64_encode(cipher, encoded))
        return rsp.error("failed to encode cipher text");

    ww::value::String v(encoded.c_str());
    return rsp.value(v, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: rsa_test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool rsa_test(const Message& msg, const Environment& env, Response& rsp)
{
    // ---------- get the keys we need ----------
    std::string rsa_public;
    if (! meta_store.get(public_encrypt_key, rsa_public))
        return rsp.error("failed to find rsa public key");

    std::string rsa_private;
    if (! meta_store.get(private_decrypt_key, rsa_private))
        return rsp.error("failed to find rsa private key");

    ww::types::ByteArray aes_key;
    if (! meta_store.get(symmetric_key, aes_key))
        return rsp.error("failed to find aes key");

    // ---------- encrypt the aes key ----------
    ww::types::ByteArray cipher;
    if (! ww::crypto::rsa::encrypt_message(aes_key, rsa_public, cipher))
        return rsp.error("failed to encrypt the key");

    // ---------- decrypt the message ----------
    ww::types::ByteArray new_aes_key;
    if (! ww::crypto::rsa::decrypt_message(cipher, rsa_private, new_aes_key))
        return rsp.error("failed to decrypt the key");

    if (aes_key != new_aes_key)
        return rsp.error("decrypted key differs from the original key");

    // ---------- return the signature ----------
    std::string encoded;
    if (! ww::crypto::b64_encode(cipher, encoded))
        return rsp.error("failed to encode cipher text");

    ww::value::String v(encoded.c_str());
    return rsp.value(v, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: hash_test
//
// test the hash and hmac functions. for the moment this only tests
// the 256 bit versions.
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool hash_test(const Message& msg, const Environment& env, Response& rsp)
{
    ww::types::ByteArray hash;
    std::string encoded_hash;

    ww::types::ByteArray hmac;
    std::string encoded_hmac;

    const ww::types::ByteArray hmackey{4, 6, 8, 5, 1, 2, 3, 4, 3, 4, 7, 8, 9, 7, 8, 0};
    const ww::types::ByteArray hmackey_badkey{0, 6, 8, 5, 1, 2, 3, 4, 3, 4, 7, 8, 9, 7, 8, 0};
    const std::string test_msg_str("Proof of Elapsed Time");
    const std::string test_msg_bad_str("Proof of Elapsed Time 2");
    const std::string expected_hmac("mO+yrlHk5HH1vyDlKuSjhTgWR0Y9Iqv1JlZW+pKDwWk=");
    const std::string expected_hash("43fTaEjBzvug9rf0RRU6anIHfgdoqNjQ/dy/jzcVcAk=");

    ww::types::ByteArray test_msg(test_msg_str.begin(), test_msg_str.end());
    ww::types::ByteArray test_msg_bad(test_msg_bad_str.begin(), test_msg_bad_str.end());

    // hash
    if (! ww::crypto::crypto_hash(test_msg, hash))
        return rsp.error("failed to compute hash");
    if (! ww::crypto::b64_encode(hash, encoded_hash))
        return rsp.error("failed to encode hash");
    if (encoded_hash != expected_hash)
        return rsp.error("failed to compute the correct hash");

    if (! ww::crypto::crypto_hash(test_msg_bad, hash))
        return rsp.error("failed to compute hash");
    if (! ww::crypto::b64_encode(hash, encoded_hash))
        return rsp.error("failed to encode hash");
    if (encoded_hash == expected_hash)
        return rsp.error("failed to compute the incorrect hash");

    // hmac
    if (! ww::crypto::crypto_hmac(test_msg, hmackey, hmac))
        return rsp.error("failed to compute hmac");
    if (! ww::crypto::b64_encode(hmac, encoded_hmac))
        return rsp.error("failed to encode hmac");
    if (encoded_hmac != expected_hmac)
        return rsp.error("failed to compute the correct hmac");

    if (! ww::crypto::crypto_hmac(test_msg, hmackey_badkey, hmac))
        return rsp.error("failed to compute hmac");
    if (! ww::crypto::b64_encode(hmac, encoded_hmac))
        return rsp.error("failed to encode hmac");
    if (encoded_hmac == expected_hmac)
        return rsp.error("failed to identify bad hmac");

    if (! ww::crypto::crypto_hmac(test_msg_bad, hmackey, hmac))
        return rsp.error("failed to compute hmac");
    if (! ww::crypto::b64_encode(hmac, encoded_hmac))
        return rsp.error("failed to encode hmac");
    if (encoded_hmac == expected_hmac)
        return rsp.error("failed to identify bad hmac");

    // pbkd
    const std::string expected_key(
        "ec/eXNCjxB/5J49/4Gq5OCCNwh1KkiA/fWo8Lifp/sCvC9ivr6SXK+rpW4cuB1Yk1ea52BdT3FEcYuI5Fdoyxg==");
    const std::string test_pw(
        "inside genius hold void transfer multiply truth market journey mention picnic stand");
    const std::string bad_pw(
        "inside genius hold void transfer multiply truth market journey mention picnic");
    const ww::types::ByteArray test_salt{
        166, 250, 20, 67, 61, 195, 91, 192, 3, 209, 21, 225, 38, 212, 162, 70
    };
    const ww::types::ByteArray bad_salt{
        0, 0, 0, 0, 61, 195, 91, 192, 3, 209, 21, 225, 38, 212, 162, 70
    };

    ww::types::ByteArray derived_key;
    std::string encoded_key;

    CONTRACT_SAFE_LOG(3, "pbkd[expected]: %s", expected_key.c_str());

    if (! ww::crypto::crypto_pbkd(test_pw, test_salt, derived_key))
        return rsp.error("failed to compute derived key");
    if (! ww::crypto::b64_encode(derived_key, encoded_key))
        return rsp.error("failed to encode hmac");
    CONTRACT_SAFE_LOG(3, "pbkd[1]: %s", encoded_key.c_str());
    if (encoded_key != expected_key)
        return rsp.error("failed to derive the correct key");

    if (! ww::crypto::crypto_pbkd(bad_pw, test_salt, derived_key))
        return rsp.error("failed to compute derived key");
    if (! ww::crypto::b64_encode(derived_key, encoded_key))
        return rsp.error("failed to encode hmac");
    CONTRACT_SAFE_LOG(3, "pbkd[2]: %s", encoded_key.c_str());
    if (encoded_key == expected_key)
        return rsp.error("failed to derive an alternate key with bad password");

    if (! ww::crypto::crypto_pbkd(test_pw, bad_salt, derived_key))
        return rsp.error("failed to compute derived key");
    if (! ww::crypto::b64_encode(derived_key, encoded_key))
        return rsp.error("failed to encode hmac");
    CONTRACT_SAFE_LOG(3, "pbkd[3]: %s", encoded_key.c_str());
    if (encoded_key == expected_key)
        return rsp.error("failed to derive an alternate key with bad salt");

    // ---------- Create the return value ----------
    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// kv store test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool kv_test_set(const Message& msg, const Environment& env, Response& rsp)
{
    ww::types::ByteArray aes_key;
    if (! meta_store.get(symmetric_key, aes_key))
        return rsp.error("failed to find aes key");

    int handle = KeyValueStore::create(aes_key);
    if (handle < 0)
        return rsp.error("failed to create the key value store");

    KeyValueStore temp_store("temp", handle);

    uint32_t value = 1;
    if (! temp_store.set(kv_test_key, value))
        return rsp.error("failed to save the value");

    ww::types::ByteArray block_id;
    if (! KeyValueStore::finalize(handle, block_id))
        return rsp.error("failed to finalize block store");

    if (! meta_store.set(kv_hash_id, block_id))
        return rsp.error("failed to save the new block identifier");

    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// kv store test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool kv_test_get(const Message& msg, const Environment& env, Response& rsp)
{
    ww::types::ByteArray aes_key;
    if (! meta_store.get(symmetric_key, aes_key))
        return rsp.error("failed to find aes key");

    ww::types::ByteArray block_id;
    if (! meta_store.get(kv_hash_id, block_id))
        return rsp.error("failed to find the new block identifier");

    int handle = KeyValueStore::open(block_id, aes_key);
    if (handle < 0)
        return rsp.error("failed to create the key value store");

    KeyValueStore temp_store("temp", handle);

    uint32_t value;
    if (! temp_store.get(kv_test_key, value))
        return rsp.error("failed to retrieve the value");

    if (value != 1)
        return rsp.error("failed to get the correct value");

    if (! KeyValueStore::finalize(handle, block_id))
        return rsp.error("failed to finalize block store");

    ww::value::Number v((double)value);
    return rsp.value(v, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// kv store test
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool privileged_test_get(const Message& msg, const Environment& env, Response& rsp)
{
    ww::types::ByteArray value;
    std::string encoded_value;

    if (! KeyValueStore::privileged_get("IdHash", value))
        return rsp.error("failed to retrieve privileged value for IdHash");
    if (! ww::crypto::b64_encode(value, encoded_value))
        return rsp.error("failed to encode value");
    if (encoded_value != env.contract_id_)
        return rsp.error("mismatched contract id");

    if (! KeyValueStore::privileged_get("ContractCode.Hash", value))
        return rsp.error("failed to retreive privileged value for ContractCode.Hash");
    if (! ww::crypto::b64_encode(value, encoded_value))
        return rsp.error("failed to encode value");
    CONTRACT_SAFE_LOG(3, "contract code hash: %s", encoded_value.c_str());

    if (! KeyValueStore::privileged_get("ContractCode.Name", encoded_value))
        return rsp.error("failed to retreive privileged value for ContractCode.Name");
    CONTRACT_SAFE_LOG(3, "contract code name: %s", encoded_value.c_str());

    if (! KeyValueStore::privileged_get("ContractCode.Nonce", encoded_value))
        return rsp.error("failed to retreive privileged value for ContractCode.Nonce");
    CONTRACT_SAFE_LOG(3, "contract code nonce: %s", encoded_value.c_str());

    return rsp.success(false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(ecdsa_test),
    CONTRACT_METHOD(extended_ecdsa_test),
    CONTRACT_METHOD(aes_test),
    CONTRACT_METHOD(rsa_test),
    CONTRACT_METHOD(hash_test),
    CONTRACT_METHOD(kv_test_set),
    CONTRACT_METHOD(kv_test_get),
    CONTRACT_METHOD(privileged_test_get),
    { NULL, NULL }
};
