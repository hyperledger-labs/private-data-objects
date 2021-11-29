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
static KeyValueStore endpoint_store("endpoint");

const std::string code_hash_key("code-hash");
const std::string secret_key("secret-key");
const std::string ledger_key("ledger-key");

bool set_ledger_key(const std::string& ledger_verifying_key)
{
    return meta_store.set(ledger_key, ledger_verifying_key);
}

bool get_ledger_key(std::string& ledger_verifying_key)
{
    if (! meta_store.get(ledger_key, ledger_verifying_key))
        return false;
    return true;
}

bool ledger_key_initialized(void)
{
    std::string key;
    if (! get_ledger_key(key))
        return false;
    if (key.length() == 0)
        return false;
    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: initialize
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool initialize_contract(const Environment& env, Response& rsp)
{
    if (! set_ledger_key(""))
        return rsp.error("failed to initialize the meta store");

    // compute the our code hash, we'll use it later for verification of endpoints
    // that must have the same code we do
    ww::types::ByteArray name;
    if (! KeyValueStore::privileged_get("ContractCode.Name", name))
        return rsp.error("failed to initialize code name");

    ww::types::ByteArray code_buffer;
    if (! KeyValueStore::privileged_get("ContractCode.Code", code_buffer))
        return rsp.error("failed to initialize code hash");

    std::copy(name.begin(), name.end(), std::back_inserter(code_buffer));

    ww::types::ByteArray code_hash;
    if (! ww::crypto::crypto_hash(code_buffer, code_hash))
        return rsp.error("failed to compute code hash");

    if (! meta_store.set(code_hash_key, code_hash))
        return rsp.error("failed to save the code hash");

    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: initialize
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define INITIALIZE_PARAMETER_SCHEMA "{\"ledger_verifying_key\":\"\"}"

bool initialize(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_CREATOR(env, rsp);
    ASSERT_SUCCESS(rsp, msg.validate_schema(INITIALIZE_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    if (ledger_key_initialized())
        return rsp.error("contract has already been initialized");

    const std::string ledger_verifying_key(msg.get_string("ledger_verifying_key"));
    if (! set_ledger_key(ledger_verifying_key))
        return rsp.error("failed to save the ledger verifying key");

    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: get_contract_metadata
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool get_contract_metadata(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_CREATOR(env, rsp);

    // we really don't need the ledger key for this operation, but
    // in general we want the initialization to happen first
    if (! ledger_key_initialized())
        return rsp.error("contract has not been initialized");

    std::string verifying_key;
    if (! KeyValueStore::privileged_get("ContractKeys.Verifying", verifying_key))
        return rsp.error("failed to retreive privileged value for ContractKeys.Verifying");

    std::string encryption_key;
    if (! KeyValueStore::privileged_get("ContractKeys.Encryption", encryption_key))
        return rsp.error("failed to retreive privileged value for ContractKeys.Encryption");

    ww::value::Object result;
    result.set_string("verifying_key", verifying_key.c_str());
    result.set_string("encryption_key", encryption_key.c_str());

    return rsp.value(result, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: get_contract_code_metadata
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool get_contract_code_metadata(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_CREATOR(env, rsp);

    // we really don't need the ledger key for this operation, but
    // in general we want the initialization to happen first
    if (! ledger_key_initialized())
        return rsp.error("contract has not been initialized");

    // returning all the information for now though only the nonce
    // should be necessary for the attestation test
    std::string code_nonce;
    if (! KeyValueStore::privileged_get("ContractCode.Nonce", code_nonce))
        return rsp.error("failed to retreive privileged value for ContractCode.Nonce");

    ww::value::Object result;
    result.set_string("code_nonce", code_nonce.c_str());

    return rsp.value(result, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: add_endpoint
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

#define ADD_ENDPOINT_PARAMETER_SCHEMA                                   \
     "{"                                                                \
          "\"contract_id\":\"\","                                       \
          "\"ledger_attestation\":{ \"contract_code_hash\":\"\", \"metadata_hash\":\"\", \"signature\":\"\" }," \
          "\"contract_metadata\":{ \"verifying_key\":\"\", \"encryption_key\":\"\" }," \
          "\"contract_code_metadata\":{ \"code_nonce\":\"\" }" \
     "}"

bool add_endpoint(const Message& msg, const Environment& env, Response& rsp)
{
    // to add an endpoint we do need the ledger key
    std::string ledger_key;
    if (! get_ledger_key(ledger_key) && ledger_key.length() > 0)
        return rsp.error("contract has not been initialized");

    // extract the parameters
    ASSERT_SUCCESS(rsp, msg.validate_schema(ADD_ENDPOINT_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string contract_id(msg.get_string("contract_id"));
    const std::string ledger_code_hash(msg.get_string("ledger_attestation.contract_code_hash"));
    const std::string ledger_meta_hash(msg.get_string("ledger_attestation.metadata_hash"));
    const std::string ledger_signature(msg.get_string("ledger_attestation.signature"));
    const std::string verifying_key(msg.get_string("contract_metadata.verifying_key"));
    const std::string encryption_key(msg.get_string("contract_metadata.encryption_key"));
    const std::string code_nonce(msg.get_string("contract_code_metadata.code_nonce"));

    // we are going to assume that the invoker of this method is the creator
    // of the contract being added so the creator id will come from the environment
    const std::string creator(env.originator_id_);

    // verify the ledger's signature on the metadata_hash and code_hash
    {
        ww::types::ByteArray buffer;
        std::copy(contract_id.begin(), contract_id.end(), std::back_inserter(buffer));
        std::copy(creator.begin(), creator.end(), std::back_inserter(buffer));
        std::copy(ledger_code_hash.begin(), ledger_code_hash.end(), std::back_inserter(buffer));
        std::copy(ledger_meta_hash.begin(), ledger_meta_hash.end(), std::back_inserter(buffer));

        ww::types::ByteArray signature;
        if (! ww::crypto::b64_decode(ledger_signature, signature))
            return rsp.error("failed to decode ledger signature");
        if (! ww::crypto::ecdsa::verify_signature(buffer, ledger_key, signature))
            return rsp.error("failed to verify ledger signature");
    }

    // verify that the code hash matches the code hash in the ledger
    {
        // we compute the merkle root using the hash of our own code
        // so we know the hash of the other if it matches
        ww::types::ByteArray decoded_code_hash;
        if (! meta_store.get(code_hash_key, decoded_code_hash))
            return rsp.error("failed to retrieve code hash");

        ww::types::ByteArray nonce(code_nonce.begin(), code_nonce.end());
        ww::types::ByteArray decoded_nonce_hash;
        if (! ww::crypto::crypto_hash(nonce, decoded_nonce_hash))
            return rsp.error("failed to hash code nonce");

        ww::types::ByteArray buffer;
        std::copy(decoded_code_hash.begin(), decoded_code_hash.end(), std::back_inserter(buffer));
        std::copy(decoded_nonce_hash.begin(), decoded_nonce_hash.end(), std::back_inserter(buffer));

        ww::types::ByteArray decoded_code_hash_root;
        if (! ww::crypto::crypto_hash(buffer, decoded_code_hash_root))
            return rsp.error("failed to create the code hash root");

        ww::types::ByteArray decoded_ledger_code_hash;
        if (! ww::crypto::b64_decode(ledger_code_hash, decoded_ledger_code_hash))
            return rsp.error("failed to decoded ledger code hash");

        if (decoded_ledger_code_hash != decoded_code_hash_root)
            return rsp.error("attestation of code hash failed");
    }

    // verify that the metadata hash matches the metadata hash in the ledger
    {
        ww::types::ByteArray idhash;
        if (! ww::crypto::b64_decode(contract_id, idhash))
            return rsp.error("failed to decode the contract id");

        ww::types::ByteArray buffer;
        std::copy(idhash.begin(), idhash.end(), std::back_inserter(buffer));
        std::copy(verifying_key.begin(), verifying_key.end(), std::back_inserter(buffer));
        std::copy(encryption_key.begin(), encryption_key.end(), std::back_inserter(buffer));

        ww::types::ByteArray computed_hash;
        if (! ww::crypto::crypto_hash(buffer, computed_hash))
            return rsp.error("failed to compute the hash for metadata comparison");

        ww::types::ByteArray decoded_ledger_meta_hash;
        if (! ww::crypto::b64_decode(ledger_meta_hash, decoded_ledger_meta_hash))
            return rsp.error("failed to decoded ledger code hash");

        if (computed_hash != decoded_ledger_meta_hash)
            return rsp.error("computed metadata hash not the same as the stored hash");
    }

    // now store the information about the endpoint
    ww::value::Object endpoint_information;
    endpoint_information.set_string("verifying_key", verifying_key.c_str());
    endpoint_information.set_string("encryption_key", encryption_key.c_str());

    std::string serialized_endpoint_information;
    if (! endpoint_information.serialize(serialized_endpoint_information))
        return rsp.error("failed to serialize endpoint information");

    if (! endpoint_store.set(contract_id, serialized_endpoint_information))
        return rsp.error("failed to save the endpoint information");

    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: send_secret
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define SEND_SECRET_PARAMETER_SCHEMA "{\"contract_id\":\"\"}"

bool send_secret(const Message& msg, const Environment& env, Response& rsp)
{
    return rsp.success(false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: receive_secret
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define RECV_SECRET_PARAMETER_SCHEMA "{\"ledger_verifying_key\":\"\"}"

bool recv_secret(const Message& msg, const Environment& env, Response& rsp)
{
    return rsp.success(false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: generate_secret
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool generate_secret(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SENDER_IS_CREATOR(env, rsp);

    std::string encoded_secret;
    if (meta_store.get(secret_key, encoded_secret))
        return rsp.error("the secret has already been generated");

    ww::types::ByteArray secret;
    if (! ww::crypto::random_identifier(secret))
        return rsp.error("failed to create secret");

    if (! ww::crypto::b64_encode(secret, encoded_secret))
        return rsp.error("failed to encode secret");

    if (! meta_store.set(secret_key, encoded_secret))
        return rsp.error("failed to save secret");

    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: reveal_secret
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define REVEAL_SECRET_PARAMETER_SCHEMA          \
     "{"                                        \
          "\"ledger_signature\":\"\""           \
     "}"

bool reveal_secret(const Message& msg, const Environment& env, Response& rsp)
{
    // two conditions must be met to reveal the secret:
    // 1) the secret must have been generated and stored in state
    // 2) the state must have been committed to the ledger

    std::string ledger_key;
    if (! get_ledger_key(ledger_key) && ledger_key.length() > 0)
        return rsp.error("contract has not been initialized");

    ASSERT_SUCCESS(rsp, msg.validate_schema(REVEAL_SECRET_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    std::string encoded_secret;
    if (! meta_store.get(secret_key, encoded_secret))
        return rsp.error("no secret has been generated");

    const std::string ledger_signature(msg.get_string("ledger_signature"));

    ww::types::ByteArray buffer;
    std::copy(env.contract_id_.begin(), env.contract_id_.end(), std::back_inserter(buffer));
    std::copy(env.state_hash_.begin(), env.state_hash_.end(), std::back_inserter(buffer));

    ww::types::ByteArray signature;
    if (! ww::crypto::b64_decode(ledger_signature, signature))
        return rsp.error("failed to decode ledger signature");
    if (! ww::crypto::ecdsa::verify_signature(buffer, ledger_key, signature))
        return rsp.error("failed to verify ledger signature");

    ww::value::String result(encoded_secret.c_str());
    return rsp.value(result, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: verify_sgx_report
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define VERIFY_SGX_REPORT_PARAMETER_SCHEMA      \
     "{"                                        \
          "\"certificate\":\"\","               \
          "\"report\":\"\","                    \
          "\"signature\":\"\""                  \
     "}"

bool verify_sgx_report(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_SUCCESS(rsp, msg.validate_schema(VERIFY_SGX_REPORT_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string certificate(msg.get_string("certificate"));
    const std::string report(msg.get_string("report"));
    const std::string signature(msg.get_string("signature"));

    CONTRACT_SAFE_LOG(3, "report: %s", report.c_str());

    bool status = verify_sgx_report(certificate.c_str(), certificate.length(),
                                   report.c_str(), report.length(),
                                   signature.c_str(), signature.length());

    ww::value::Boolean result(status);
    return rsp.value(result, false);
}



// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(initialize),
    CONTRACT_METHOD(get_contract_metadata),
    CONTRACT_METHOD(get_contract_code_metadata),
    CONTRACT_METHOD(add_endpoint),
    CONTRACT_METHOD(generate_secret),
    CONTRACT_METHOD(recv_secret),
    CONTRACT_METHOD(send_secret),
    CONTRACT_METHOD(reveal_secret),
    CONTRACT_METHOD(verify_sgx_report),
    { NULL, NULL }
};
