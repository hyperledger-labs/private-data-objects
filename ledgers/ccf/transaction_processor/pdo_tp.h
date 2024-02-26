/* Copyright 2020 Intel Corporation
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

// This app's includes
#include "enclave_registry.h"
#include "contract_registry.h"
#include "ccl_registry.h"

// CCF
#include "crypto/key_pair.h"
#include "crypto/rsa_key_pair.h"
#include "crypto/hash_provider.h"
#include "app_interface.h"
#include "common_auth_policies.h"
#include "crypto/verifier.h"
#include "crypto/sha256.h"
#include "ds/hash.h"
#include "ds/hex.h"
#include "historical_queries_adapter.h"
#include "http_query.h"
#include "indexing/strategies/seqnos_by_key_bucketed.h"
#include "indexing/strategy.h"
#include "json_handler.h"
#include "version.h"

// others
#include <map>
#include <sgx_quote.h>

using namespace std;
using namespace ccf;
using namespace crypto;

namespace ccfapp
{

    struct Get_Ledger_Key {
        struct Out {
        string verifying_key;
        };
    };

    DECLARE_JSON_TYPE(Get_Ledger_Key::Out);
    DECLARE_JSON_REQUIRED_FIELDS(Get_Ledger_Key::Out, verifying_key);

    // utility constants
    const string PDO_ENCLAVE_EXPECTED_SGX_MEASUREMENTS{"pdo_enclave_expected_sgx_measurements"};
    const string PDO_ENCLAVE_CHECK_ATTESTATION_FLAG{"pdo_enclave_check_attestation_flag"};
    const string OK_QUOTE_STATUS{"OK"};
    const string GROUP_OUT_OF_DATE_QUOTE_STATUS{"GROUP_OUT_OF_DATE"};
    const string SW_HARDENING_NEEDED_QUOTE_STATUS{"SW_HARDENING_NEEDED"};
    const int BASENAME_SIZE{32};
    const int ORIGINATOR_KEY_HASH_SIZE{64};

    // test method
    static constexpr auto PingMe = "ping";

    //methods that write
    static constexpr auto REGISTER_ENCLAVE = "register_enclave";
    static constexpr auto SET_CONTRACT_ENCLAVE_CHECK_ATTESTATION_FLAG = "set_contract_enclave_check_attestatation_flag";
    static constexpr auto SET_CONTRACT_ENCLAVE_EXPECTED_SGX_MEASUREMENTS = "set_contract_enclave_expected_sgx_measurements";
    static constexpr auto REGISTER_CONTRACT = "register_contract";
    static constexpr auto ADD_ENCLAVE_TO_CONTRACT ="add_enclave_to_contract";
    static constexpr auto INITIALIZE_CONTRACT_STATE ="ccl_initialize";
    static constexpr auto UPDATE_CONTRACT_STATE ="ccl_update";

    //methods that read the tables, used by PDO to verify write transactions
    static constexpr auto VERIFY_ENCLAVE_REGISTRATION = "verify_enclave_registration";
    static constexpr auto GET_CONTRACT_PROVISIONING_INFO = "get_contract_provisioning_info";
    static constexpr auto GET_CONTRACT_INFO = "get_contract_info";
    static constexpr auto GET_CURRENT_STATE_INFO_FOR_CONTRACT = "get_current_state_info_for_contract";
    static constexpr auto GET_DETAILS_ABOUT_STATE = "get_details_about_state";

    //methods that create and read ledger authority keys.
    static constexpr auto GEN_SIGNING_KEY = "generate_signing_key_for_read_payloads";
    static constexpr auto GET_LEDGER_KEY = "get_ledger_verifying_key";

    class TPHandlerRegistry  : public UserEndpointRegistry
    {
        private:

            kv::Map<string, ContractEnclaveExpectedSGXMeasurements> contract_enclave_expected_sgx_measurements;
                        // There is a single entry with key PDO_ENCLAVE_EXPECTED_SGX_MEASUREMENTS.
                        // Only the CCF Governing body can update this entry.
                        // Can be generalized if multiple enclave "types" need to be verified.
                        // Also, the expected measurements are used only if the check_attestation_flag is True
            kv::Map<string, ContractEnclaveAttestionCheckFlag> contract_enclave_check_attestation_flag;
                        // key is PDO_ENCLAVE_CHECK_ATTESTATION_FLAG
            kv::Map<string, EnclaveInfo> enclavetable; // key is encalve_id
            kv::Map<string, ContractInfo> contracttable; // key is contract_id
            kv::Map<string, ContractStateInfo> ccltable; // key is contract_id + state_hash (string addition)
            kv::Map<string, map<string, string>> signer; //There is at most one entry in this map. if there is an
                                                         //entry key="signer".  value is pubk:privk

            // functions to verify signatures, only wite methods sign transactions, read methods do not.
            bool verify_pdo_transaction_signature_register_enclave(
                const vector<uint8_t>& signature,
                const string & verifying_key,
                const EnclaveInfo & enclave_info);

            /* RSA sig verification */
            bool verify_rsa_sig(
                vector<uint8_t> signature,
                const string & verifying_key,
                const vector<uint8_t> & contents);

            /* ECDSA sig verification */
            bool verify_sig(
                vector<uint8_t> signature,
                const string & verifying_key,
                const vector<uint8_t> & contents);

            bool verify_sig_static(
                vector<uint8_t> signature,
                const PublicKeyPtr & pubk_verifier,
                const vector<uint8_t>& contents);

            bool verify_ias_signature(
                const string& signature,
                const string& ias_public_key,
                const string& verification_report_string);

            bool verify_pdo_transaction_signature_register_contract(
                const vector<uint8_t>& signature,
                const string & verifying_key,
                const vector<uint8_t>& contract_code_hash,
                const string & nonce,
                const vector<string> & provisioning_service_ids);

            bool verify_pdo_transaction_signature_add_enclave(
                const vector<uint8_t>& signature,
                const string & verifying_key,
                const string & contract_id,
                const string &  enclave_info_json_string);

            bool verify_enclave_signature_add_enclave(
                const string& signature,
                const PublicKeyPtr & pubk_verifier,
                const string & contract_creator_key,
                const string & contract_id,
                const vector<ProvisioningKeysToSecretMap> & prov_key_maps,
                const string & encrypted_state_encryption_key);

            bool verify_creator_signature_initialize_contract_state(
                const vector<uint8_t>& contract_enclave_signature,
                const vector<uint8_t>& contract_creator_signature,
                const string & contract_creator_verifying_key);

            bool verify_enclave_signature_initialize_contract_state(
                const vector<uint8_t>& nonce,
                const string & contract_id,
                const vector<uint8_t>& initial_state_hash,
                const vector<uint8_t>& contract_code_hash,
                const vector<uint8_t>& message_hash,
                const vector<uint8_t>& contract_metadata_hash,
                const string & contract_creator_verifying_key,
                const vector<uint8_t>& enclave_signature,
                const PublicKeyPtr & enclave_verifying_key);

            bool verify_enclave_signature_update_contract_state(
                const vector<uint8_t>& nonce,
                const vector<uint8_t>& contract_code_hash,
                const StateUpdateInfo & state_update_info,
                const vector<uint8_t>& enclave_signature,
                const PublicKeyPtr & enclave_verifying_key);

            KeyPairPtr ledger_signer_local;

            string sign_document(const string& document);
            string vector_to_string(const vector<uint8_t>& vec);

        public:

            TPHandlerRegistry (ccfapp::AbstractNodeContext& context);
            map<string, PublicKeyPtr> enclave_pubk_verifier; // the key is the enclave verifying key
    };

}
