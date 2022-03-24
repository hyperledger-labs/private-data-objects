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

#include "enclave_registry.h"
#include "contract_registry.h"
#include "ccl_registry.h"

#include "crypto/key_pair.h"
#include "ds/buffer.h"

#include "ccf/app_interface.h"
#include "ccf/user_frontend.h"
#include "apps/utils/metrics_tracker.h"

#include <map>

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

    // test method
    static constexpr auto PingMe = "ping";

    //methods that write
    static constexpr auto REGISTER_ENCLAVE = "register_enclave";
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

            bool verify_sig(
                vector<uint8_t> signature,
                const string & verifying_key,
                const vector<uint8_t> & contents);

            bool verify_sig_static(
                vector<uint8_t> signature,
                const PublicKeyPtr & pubk_verifier,
                const vector<uint8_t>& contents);

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

    class TransactionProcessor : public ccf::RpcFrontend
    {
    private:
        TPHandlerRegistry  tp_handlers;

    public:
        TransactionProcessor(ccf::NetworkTables& network, ccfapp::AbstractNodeContext& context):
            ccf::RpcFrontend(*network.tables, tp_handlers),
            tp_handlers(context)
        {}
    };

}
