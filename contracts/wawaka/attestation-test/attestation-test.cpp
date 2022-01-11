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

#include "Attestation.h"
#include "Cryptography.h"
#include "Environment.h"
#include "KeyValue.h"
#include "Message.h"
#include "Response.h"
#include "Secret.h"
#include "StateReference.h"
#include "Types.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

#include "contract/base.h"
#include "contract/attestation.h"

static KeyValueStore secret_store("secret");

const std::string secret_key("secret-key");

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: initialize
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool initialize_contract(const Environment& env, Response& rsp)
{
    ASSERT_SUCCESS(rsp, ww::contract::base::initialize_contract(env),
                   "failed to initialize the base contract");
    ASSERT_SUCCESS(rsp, ww::contract::attestation::initialize_contract(env),
                   "failed to initialize the attestation contract");

    // save the code hash for verifying attestations
    ww::types::ByteArray code_hash;
    ASSERT_SUCCESS(rsp, ww::contract::attestation::compute_code_hash(code_hash),
                   "failed to compute the code hash");
    ASSERT_SUCCESS(rsp, ww::contract::attestation::set_code_hash(code_hash),
                   "failed to save the code hash");

    // generate and store a secret
    ww::types::ByteArray secret;
    if (! ww::crypto::random_identifier(secret))
        return rsp.error("failed to create secret");

    std::string encoded_secret;
    if (! ww::crypto::b64_encode(secret, encoded_secret))
        return rsp.error("failed to encode secret");

    if (! secret_store.set(secret_key, encoded_secret))
        return rsp.error("failed to save secret");

    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: initialize
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define INITIALIZE_PARAMETER_SCHEMA "{" SCHEMA_KW(ledger_verifying_key, "") "}"

bool initialize(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_UNINITIALIZED(rsp);
    ASSERT_SENDER_IS_CREATOR(env, rsp);
    ASSERT_SUCCESS(rsp, msg.validate_schema(INITIALIZE_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string ledger_verifying_key(msg.get_string("ledger_verifying_key"));
    ASSERT_SUCCESS(rsp, ww::contract::attestation::set_ledger_key(ledger_verifying_key),
                   "failed to save the ledger verifying key");

    ASSERT_SUCCESS(rsp, ww::contract::base::mark_initialized(), "initialization failed");

    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: send_secret
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define SEND_SECRET_PARAMETER_SCHEMA "{" SCHEMA_KW(contract_id,"") "}"

bool send_secret(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    ASSERT_SUCCESS(rsp, msg.validate_schema(SEND_SECRET_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string contract_id(msg.get_string("contract_id"));
    std::string verifying_key, encryption_key;
    ASSERT_SUCCESS(rsp, ww::contract::attestation::get_endpoint(contract_id, verifying_key, encryption_key),
                   "unknown contract");

    std::string encoded_secret;
    if (! secret_store.get(secret_key, encoded_secret))
        return rsp.error("failed to get the secret");

    ww::value::Object result;

    ww::value::StateReference reference(env);
    ww::value::Object serialized_reference;
    ASSERT_SUCCESS(rsp, reference.serialize(serialized_reference), "failed to serialize state reference");
    ASSERT_SUCCESS(rsp, result.set_value("reference", serialized_reference), "failed to save state reference");

    ww::value::Object secret;
    ASSERT_SUCCESS(rsp, ww::secret::send_secret(encryption_key, encoded_secret, secret), "failed to encrypt secret");
    ASSERT_SUCCESS(rsp, result.set_value("secret", secret), "failed to save secret");

    return rsp.value(result, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: receive_secret
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define RECV_SECRET_PARAMETER_SCHEMA                    \
    "{"                                                 \
        "\"reference\":" STATE_REFERENCE_SCHEMA ","     \
        "\"secret\":" CONTRACT_SECRET_SCHEMA            \
    "}"

bool recv_secret(const Message& msg, const Environment& env, Response& rsp)
{
    std::string s;
    msg.serialize(s);
    CONTRACT_SAFE_LOG(3, "SECRET: %s", s.c_str());

    ASSERT_INITIALIZED(rsp);
    ASSERT_SUCCESS(rsp, msg.validate_schema(RECV_SECRET_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    ww::value::Object secret;
    ASSERT_SUCCESS(rsp, msg.get_value("secret", secret), "failed to get secret parameter");

    ww::value::StateReference reference;
    ww::value::Object serialized_reference;
    ASSERT_SUCCESS(rsp, msg.get_value("reference", serialized_reference), "failed to get reference");
    ASSERT_SUCCESS(rsp, reference.deserialize(serialized_reference), "failed to deserialize reference");

    std::string decryption_key;
    ASSERT_SUCCESS(rsp, KeyValueStore::privileged_get("ContractKeys.Decryption", decryption_key),
                   "failed to retreive privileged value for ContractKeys.Deccryption");

    std::string encoded_secret;
    ASSERT_SUCCESS(rsp, ww::secret::recv_secret(decryption_key, secret, encoded_secret),
                   "failed to decrypt the secret");

    ASSERT_SUCCESS(rsp, secret_store.set(secret_key, encoded_secret),
                   "failed to save secret");

    reference.add_to_response(rsp);
    return rsp.success(true);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: reveal_secret
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define REVEAL_SECRET_PARAMETER_SCHEMA "{" SCHEMA_KW(ledger_signature,"") "}"

bool reveal_secret(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    ASSERT_SENDER_IS_CREATOR(env, rsp);

    // two conditions must be met to reveal the secret:
    // 1) the secret must have been generated and stored in state
    // 2) the state must have been committed to the ledger

    std::string ledger_key;
    if (! ww::contract::attestation::get_ledger_key(ledger_key) && ledger_key.length() > 0)
        return rsp.error("contract has not been initialized");

    ASSERT_SUCCESS(rsp, msg.validate_schema(REVEAL_SECRET_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string ledger_signature(msg.get_string("ledger_signature"));

    ww::types::ByteArray buffer;
    std::copy(env.contract_id_.begin(), env.contract_id_.end(), std::back_inserter(buffer));
    std::copy(env.state_hash_.begin(), env.state_hash_.end(), std::back_inserter(buffer));

    ww::types::ByteArray signature;
    if (! ww::crypto::b64_decode(ledger_signature, signature))
        return rsp.error("failed to decode ledger signature");
    if (! ww::crypto::ecdsa::verify_signature(buffer, ledger_key, signature))
        return rsp.error("failed to verify ledger signature");

    std::string encoded_secret;
    ASSERT_SUCCESS(rsp, secret_store.get(secret_key, encoded_secret),
                   "failed to retrieve the stored secret");

    ww::value::String result(encoded_secret.c_str());
    return rsp.value(result, false);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// NAME: verify_sgx_report
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define VERIFY_SGX_REPORT_PARAMETER_SCHEMA      \
     "{"                                        \
         SCHEMA_KW(certificate, "") ","         \
         SCHEMA_KW(report, "") ","              \
         SCHEMA_KW(signature, "")               \
     "}"

bool verify_sgx_report(const Message& msg, const Environment& env, Response& rsp)
{
    ASSERT_INITIALIZED(rsp);
    ASSERT_SENDER_IS_CREATOR(env, rsp);

    ASSERT_SUCCESS(rsp, msg.validate_schema(VERIFY_SGX_REPORT_PARAMETER_SCHEMA),
                   "invalid request, missing required parameters");

    const std::string certificate(msg.get_string("certificate"));
    const std::string report(msg.get_string("report"));
    const std::string signature(msg.get_string("signature"));

    // CONTRACT_SAFE_LOG(3, "report: %s", report.c_str());

    bool status = ww::attestation::verify_sgx_report(certificate, report, signature);
    if (! status)
        return rsp.error("failed to verify the report signature");

    ww::value::Object result;
    status = ww::attestation::parse_sgx_report(report, result);
    if (! status)
        return rsp.error("failed to parse the sgx report");

    return rsp.value(result, false);
}



// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(initialize),
    CONTRACT_METHOD2(get_contract_metadata, ww::contract::attestation::get_contract_metadata),
    CONTRACT_METHOD2(get_contract_code_metadata, ww::contract::attestation::get_contract_code_metadata),
    CONTRACT_METHOD2(add_endpoint, ww::contract::attestation::add_endpoint),
    CONTRACT_METHOD(recv_secret),
    CONTRACT_METHOD(send_secret),
    CONTRACT_METHOD(reveal_secret),
    CONTRACT_METHOD(verify_sgx_report),
    { NULL, NULL }
};
