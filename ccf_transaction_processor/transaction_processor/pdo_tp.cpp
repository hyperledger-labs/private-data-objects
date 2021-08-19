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

#include "pdo_tp.h"

using namespace std;
using namespace ccf;
using namespace tls;


namespace ccfapp
{

    TPHandlerRegistry ::TPHandlerRegistry (kv::Store& store):
        UserHandlerRegistry(store),
        enclavetable(store.create<string, EnclaveInfo>("enclaves")),
        contracttable(store.create<string, ContractInfo>("contracts")),
        ccltable(store.create<string, ContractStateInfo>("ccl_updates")),
        signer(store.create<string, map<string, string>>("signer"))
    {
        ledger_signer_local = NULL;
    }

    string TPHandlerRegistry ::sign_document(const string& document){
        vector<uint8_t> doc_vector(document.begin(), document.end());
        auto sign = ledger_signer_local->sign(doc_vector);
        return b64_from_raw(sign.data(), sign.size());
    }

    void TPHandlerRegistry::init_handlers(kv::Store& store){

        UserHandlerRegistry::init_handlers(store);

        //======================================================================================================
        // ping handler implementation
        auto ping = [this](kv::Tx& tx, const nlohmann::json& params) {
            return make_success(true);
        };

        //======================================================================================================
        // gen_signing_key implementation
        auto gen_signing_key = [this](kv::Tx& tx, const nlohmann::json& params) {

            auto signer_view = tx.get_view(signer);

            // keys already exist, globally commited
            auto signer_global = signer_view->get_globally_committed("signer");
            if (signer_global.has_value()){
                return make_success("Ledger signing keys exist and globally committed. Use get_ledger_verifying_key \
                    to get the verifying keys");
            }

            // keys exist locally, scheduled for globally commit
            auto signer_local = signer_view->get("signer");
            if (signer_local.has_value()){
                return make_success("Ledger signing keys exist and scheduled for global commit. \
                    Use get_ledger_verifying_key to check the status of global commit");
            }

            // create new keys and schedule for global commit
            try{
                auto kp = make_key_pair(CurveImpl::secp256k1_mbedtls);
                auto privk_pem = kp->private_key_pem();
                auto pubk_pem = kp->public_key_pem();
                map<string, string> key_pair;
                key_pair["privk"] = privk_pem.str();
                key_pair["pubk"] = pubk_pem.str();
                signer_view->put("signer", key_pair);
                return make_success("Ledger signing keys created locally and scheduled for global commit. \
                    Use get_ledger_verifying_key to check the status of global commit");
            } catch(...){
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Unable to create ledger Key");
            }
        };

        //======================================================================================================
        // get_ledger_key implementation
        auto get_ledger_key = [this](kv::Tx& tx, const nlohmann::json& params) {
            auto signer_view = tx.get_view(signer);

            auto signer_global = signer_view->get_globally_committed("signer");
            if (signer_global.has_value()){
                try{
                    auto key_pair = signer_global.value();
                    if (ledger_signer_local == NULL){
                        auto privk_pem = tls::Pem(key_pair["privk"]);
                        ledger_signer_local = make_key_pair(privk_pem, nullb, false);
                    }
                    return make_success(Get_Ledger_Key::Out{key_pair["pubk"]});
                }
                catch(...){
                    return make_error(
                        HTTP_STATUS_BAD_REQUEST, "Unable to locate ledger Key despite global commit");
                }
            }

            // keys already exist, but not globally commited
            auto signer_local = signer_view->get("signer");
            if (signer_local.has_value()){
                return make_error(
                    HTTP_STATUS_BAD_REQUEST,"Ledger signing key exist locally, and scheduled for globally commit. \
                    Verifying keys will be visible only after global commit. Try again in a short while");
            }else{
                return make_error(
                    HTTP_STATUS_BAD_REQUEST,"Ledger signing keys not created yet");
            }
        };

        //======================================================================================================
        // register enclave handler implementation
        auto register_enclave = [this](kv::Tx& tx, const nlohmann::json& params) {
            const auto in = params.get<Register_enclave::In>();

            // Capture  the current view of the K-V store
            auto enclave_view = tx.get_view(enclavetable);

            // Check if enclave was previously registered
            auto enclave_r = enclave_view->get(in.verifying_key);
            if (enclave_r.has_value())
            {
            return make_error(
                HTTP_STATUS_BAD_REQUEST, "Enclave already registered");
            }

            // Verify enclave data
            string proof_data = in.proof_data;
            if (proof_data.empty()) {
                // Enclave proof data is empty - simulation mode
            }else{
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Only simulation mode is currently supported");
            }

            // collect the enclave data to be stored
            EnclaveInfo new_enclave;
            try{
                new_enclave.verifying_key = in.verifying_key;
                new_enclave.encryption_key = in.encryption_key;
                new_enclave.proof_data = in.proof_data;
                new_enclave.enclave_persistent_id = in.enclave_persistent_id;
                new_enclave.registration_block_context = in.registration_block_context;
                new_enclave.organizational_info=in.organizational_info;
                new_enclave.EHS_verifying_key = in.EHS_verifying_key;
            }
            catch(...){
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Enclave registration data is incomplete");
            }

            // Verify Pdo transaction signature
            if (!verify_pdo_transaction_signature_register_enclave(in.signature, in.EHS_verifying_key, new_enclave)){
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Invalid PDO payload signature");
            }

            //store the data in the KV store
            enclave_view->put(in.verifying_key, new_enclave);

            //create signature verifier for this enclave and cache it
            const auto public_key_pem = tls::Pem(CBuffer(in.verifying_key));
            this->enclave_pubk_verifier[in.verifying_key] = tls::make_public_key(public_key_pem, false);

            return make_success(true);
        };

        //======================================================================================================
        // register contract handler implementation
        auto register_contract = [this](kv::Tx& tx, const nlohmann::json& params) {
            const auto in = params.get<Register_contract::In>();

            // Capture  the current view
            auto contract_view = tx.get_view(contracttable);

            // Check if enclave was previously registered
            auto contract_r = contract_view->get(in.contract_id);
            if (contract_r.has_value())
            {
            return make_error(
                HTTP_STATUS_BAD_REQUEST, "Contract already registered");
            }

            // Verify Pdo transaction signature
            if (!verify_pdo_transaction_signature_register_contract(in.signature, in.contract_creator_verifying_key_PEM, \
                    in.contract_code_hash, in.nonce, in.provisioning_service_ids)){
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Invalid PDO payload signature");
            }

            // collect the contract data to be stored
            ContractInfo new_contract;
            try{
                new_contract.contract_id = in.contract_id;
                new_contract.contract_code_hash = in.contract_code_hash;
                new_contract.contract_creator_verifying_key_PEM = in.contract_creator_verifying_key_PEM;
                new_contract.provisioning_service_ids = in.provisioning_service_ids;
                new_contract.is_active = true;
                new_contract.current_state_hash=std::vector<uint8_t>{};
                }
            catch(...){
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Contract registration data is incomplete");
            }

            //store the data
            contract_view->put(in.contract_id, new_contract);

            // No need to commit the Tx, this is automatically taken care of !

            return make_success(true);
        };

        //======================================================================================================
        // add_enclave (to contract) handler implementation
        auto add_enclave = [this](kv::Tx& tx, const nlohmann::json& params) {

            const auto in = params.get<Add_enclave::In>();

            // Capture  the current view of contract and encalve tables
            auto contract_view = tx.get_view(contracttable);
            auto enclave_view = tx.get_view(enclavetable);

            // ensure that contract was previously registered
            auto contract_r = contract_view->get(in.contract_id);
            if (!contract_r.has_value()) {
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Contract not yet registered");
            }
            auto contract_info = contract_r.value();

            // Verify Pdo transaction signature (ensures that the contract ownder is the one adding encalves)
            if (!verify_pdo_transaction_signature_add_enclave(in.signature, contract_info.contract_creator_verifying_key_PEM, \
                    in.contract_id, in.enclave_info)){
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Invalid PDO payload signature");
            }

            // Parse the enclave info json string
            std::vector<ContractEnclaveInfo> enclave_info_array;
            try {
                auto j = nlohmann::json::parse(in.enclave_info);
                enclave_info_array = j.get<std::vector<ContractEnclaveInfo>>();
            }
            catch(...){
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Unable to parse ContractEnclaveInfo Json");
            }

            // verify enclave_info_array

            //unsure if this check is needed, but keeping it for now
            if (enclave_info_array.size() == 0) {
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Provide at least one encalve to add to contract");
            }

            // check each element of the array
            for (auto enclave_info_temp: enclave_info_array){

                // check contract id contained in enclave info
                if (enclave_info_temp.contract_id != contract_info.contract_id){
                    return make_error(
                        HTTP_STATUS_BAD_REQUEST, "Enclave info has invalid contract id");
                }

                //ensure enclave is registered
                auto enclave_r = enclave_view->get(enclave_info_temp.contract_enclave_id);
                if (!enclave_r.has_value()){
                    return make_error(
                        HTTP_STATUS_BAD_REQUEST, "Enclave not yet registered");
                }
                auto enclave_info_ledger = enclave_r.value();

                //check if this enclave has already been added to the contract
                for (auto enclave_in_contract: contract_info.enclave_info){
                    if (enclave_info_temp.contract_enclave_id == enclave_in_contract.contract_enclave_id) {
                        return make_error(
                            HTTP_STATUS_BAD_REQUEST, "Enclave already part of contract");
                    }
                }

                //verify enclave signature
                if (!verify_enclave_signature_add_enclave(enclave_info_temp.signature, this->enclave_pubk_verifier[enclave_r.value().verifying_key], \
                    contract_info.contract_creator_verifying_key_PEM, in.contract_id, enclave_info_temp.provisioning_key_state_secret_pairs, \
                    enclave_info_temp.encrypted_state_encryption_key)){

                    return make_error( HTTP_STATUS_BAD_REQUEST, "Invalid enclave signature");
                }

                //all good, add enclave to contract
                contract_info.enclave_info.push_back(enclave_info_temp);
            }

            //store the data
            contract_view->put(in.contract_id, contract_info);

            return make_success(true);
        };

        //======================================================================================================
        // update contract state (ccl tables) handler implementation
        auto initialize_contract_state = [this](kv::Tx& tx, const nlohmann::json& params) {

            const auto in = params.get<Initialize_contract_state::In>();

            // Capture  the current view of all tables
            auto contract_view = tx.get_view(contracttable);
            auto enclave_view = tx.get_view(enclavetable);
            auto ccl_view = tx.get_view(ccltable);

            auto contract_r = contract_view->get(in.contract_id);
            auto enclave_r = enclave_view->get(in.contract_enclave_id);

            // ensure that the contract is registered
            if (!contract_r.has_value()) {
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Contract not yet registered");
            }
            auto contract_info = contract_r.value();

            //ensure that the contract is active
            if (!contract_info.is_active) {
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Contract has been turned inactive. No more upates permitted");
            }

            // ensure that the contract state was not previously initialized
            if (contract_info.current_state_hash.size() != 0) {
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Contract has already been initialized");
            }

            // ensure that the enclave is part of the contract (no need to separately check if enclave is registered)
            bool is_enclave_in_contract = false;
            for (auto enclave_in_contract: contract_info.enclave_info)
            {
                if (in.contract_enclave_id == enclave_in_contract.contract_enclave_id)
                {
                    is_enclave_in_contract = true;
                    break;
                }
            }

            if (! is_enclave_in_contract)
            {
                return make_error(
                        HTTP_STATUS_BAD_REQUEST, "Enclave used for state update not part of contract");
            }

            // signature check ensures that the operation can only be performed by the contract creator
            // only need to sign the enclave signature
            if (! verify_creator_signature_initialize_contract_state(
                    in.contract_enclave_signature,
                    in.creator_signature,
                    contract_info.contract_creator_verifying_key_PEM))
            {
                return make_error(HTTP_STATUS_BAD_REQUEST, "Invalid PDO payload signature");
            }

            // verify contract enclave signature. This signature also ensures (via the notion of channel ids) that
            // the contract invocation was performed by the transaction submitter.
            if (! verify_enclave_signature_initialize_contract_state(
                    in.nonce,
                    in.contract_id,
                    in.initial_state_hash,
                    contract_info.contract_code_hash,
                    in.message_hash,
                    in.metadata_hash,
                    contract_info.contract_creator_verifying_key_PEM,
                    in.contract_enclave_signature,
                    this->enclave_pubk_verifier[enclave_r.value().verifying_key]))
            {
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Invalid enclave signature for contract state initialize operation");
            }

            // store update info in ccl tables
            ContractStateInfo contract_state_info;
            contract_state_info.transaction_id = in.nonce;
            contract_state_info.message_hash = in.message_hash;
            contract_state_info.previous_state_hash = {};
            contract_state_info.dependency_list = {};

            const string state_hash_string(in.initial_state_hash.begin(), in.initial_state_hash.end());
            const string key_for_put = in.contract_id + state_hash_string;

            ccl_view->put(key_for_put, contract_state_info);

            // update the latest state hash known to CCF (with the incoming state hash)
            contract_info.current_state_hash = in.initial_state_hash;
            contract_view->put(in.contract_id, contract_info);

            return make_success(true);
        };

        //======================================================================================================
        // update contract state (ccl tables) handler implementation
        auto update_contract_state = [this](kv::Tx& tx, const nlohmann::json& params) {

            const auto in = params.get<Update_contract_state::In>();


            // parse the state update info json string
            StateUpdateInfo state_update_info;
            try {
                auto j = nlohmann::json::parse(in.state_update_info);
                state_update_info = j.get<StateUpdateInfo>();
            }
            catch(...){
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Unable to parse StateUpdateInfo json string");
            }


            // Capture  the current view of all tables
            auto contract_view = tx.get_view(contracttable);
            auto enclave_view = tx.get_view(enclavetable);
            auto ccl_view = tx.get_view(ccltable);

            auto contract_r = contract_view->get(state_update_info.contract_id);
            auto enclave_r = enclave_view->get(in.contract_enclave_id);

            // ensure that the contract is registered
            if (!contract_r.has_value()) {
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Contract not yet registered");
            }
            auto contract_info = contract_r.value();

            //ensure that the contract is active
            if (!contract_info.is_active) {
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Contract has been turned inactive. No more upates permitted");
            }

            // ensure that the enclave is part of the contract (no need to separately check if enclave is registered)
            bool is_enclave_in_contract = false;
            for (auto enclave_in_contract: contract_info.enclave_info){
                if (in.contract_enclave_id == enclave_in_contract.contract_enclave_id) {
                    is_enclave_in_contract = true;
                    break;
                }
            }
            if (!is_enclave_in_contract) {
                return make_error(
                        HTTP_STATUS_BAD_REQUEST, "Enclave used for state update not part of contract");
            }

            // Ensure the following:
            // 1. the previous state hash (from incoming data) is the latest state hash known to CCF (this also ensures that
            //                there was an init)
            // 2. depedencies are met (meaning these transactions have been committed in the past)
            // 3. there is a change in state, else nothing to commit
            if (state_update_info.previous_state_hash != contract_info.current_state_hash){
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Update can be performed only on the latest state registered with the ledger");
            }

            for (auto dep: state_update_info.dependency_list){
                auto dep_r = ccl_view->get(dep.contract_id+ string(dep.state_hash.begin(), dep.state_hash.end()));
                if (!dep_r.has_value()) {
                    return make_error(
                        HTTP_STATUS_BAD_REQUEST, "Unknown CCL dependencies. Cannot commit state");
                }
            }

            if (state_update_info.current_state_hash == contract_info.current_state_hash){
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Update can be commited only if there is a change in state");
            }

            // verify contract enclave signature. This signature also ensures (via the notion of channel ids) that
            // the contract invocation was performed by the transaction submitter.
            if (!verify_enclave_signature_update_contract_state(
                    in.nonce,
                    contract_info.contract_code_hash,
                    state_update_info,
                    in.contract_enclave_signature,
                    this->enclave_pubk_verifier[enclave_r.value().verifying_key]))
            {
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Invalid enclave signature for contract update operation");
            }


            // store update info in ccl tables
            ContractStateInfo contract_state_info;
            contract_state_info.transaction_id = in.nonce;
            contract_state_info.message_hash = state_update_info.message_hash;
            contract_state_info.previous_state_hash = state_update_info.previous_state_hash;
            contract_state_info.dependency_list = state_update_info.dependency_list;
            string key_for_put =  state_update_info.contract_id + \
                string(state_update_info.current_state_hash.begin(), state_update_info.current_state_hash.end());
            ccl_view->put(key_for_put, contract_state_info);

            // update the latest state hash known to CCF (with the incoming state hash)
            contract_info.current_state_hash = state_update_info.current_state_hash;
            contract_view->put(state_update_info.contract_id, contract_info);

            return make_success(true);

        };


        ///======================================================================================================
        // verify enclave handler implementation
        auto verify_enclave = [this](kv::Tx& tx, const nlohmann::json& params) {
            const auto in = params.get<Verify_enclave::In>();
            auto enclave_view = tx.get_view(enclavetable);
            auto enclave_r = enclave_view->get_globally_committed(in.enclave_id);

            if (enclave_r.has_value())
            {
                if (ledger_signer_local == NULL) {
                    auto signer_view = tx.get_view(signer);
                    auto signer_global = signer_view->get_globally_committed("signer");
                    if (signer_global.has_value()){
                        auto key_pair = signer_global.value();
                        auto privk_pem = tls::Pem(key_pair["privk"]);
                        ledger_signer_local = make_key_pair(privk_pem, nullb, false);
                    }
                    else {
                        return make_error(
                            HTTP_STATUS_BAD_REQUEST, "Unable to locate ledger authority for signing read rpcs");
                    }
                }

                string doc_to_sign;
                doc_to_sign += in.enclave_id;
                doc_to_sign += enclave_r.value().encryption_key;
                doc_to_sign += enclave_r.value().proof_data;
                doc_to_sign += enclave_r.value().registration_block_context;
                doc_to_sign += enclave_r.value().EHS_verifying_key;
                auto signature = TPHandlerRegistry ::sign_document(doc_to_sign);

                return make_success(Verify_enclave::Out{in.enclave_id, enclave_r.value().encryption_key, \
                enclave_r.value().proof_data, enclave_r.value().registration_block_context, \
                enclave_r.value().EHS_verifying_key, signature});
            }
            return make_error(
                HTTP_STATUS_BAD_REQUEST, "Enclave not found");

        };

        //======================================================================================================
        // get_contract_provisioning_info handler implementation
        auto get_contract_provisioning_info = [this](kv::Tx& tx, const nlohmann::json& params) {
            const auto in = params.get<Get_contract_provisioning_info::In>();
            auto view = tx.get_view(contracttable);
            auto contract_r = view->get_globally_committed(in.contract_id);

            if (contract_r.has_value())
            {
                if (ledger_signer_local == NULL) {
                    auto signer_view = tx.get_view(signer);
                    auto signer_global = signer_view->get_globally_committed("signer");
                    if (signer_global.has_value()){
                        auto key_pair = signer_global.value();
                        auto privk_pem = tls::Pem(key_pair["privk"]);
                        ledger_signer_local = make_key_pair(privk_pem, nullb, false);
                    }
                    else {
                        return make_error(
                            HTTP_STATUS_BAD_REQUEST, "Unable to locate ledger authority for signing read rpcs");
                    }
                }

                auto contract_code_hash = contract_r.value().contract_code_hash;
                auto encoded_code_hash = b64_from_raw(contract_code_hash.data(), contract_code_hash.size());

                // JSON is a notorious difficult format for signing; however, the complexity
                // of the structure we need to sign makes this about the only good way to
                // do the signing
                // NOTE: nlohmann serialization uses no spaces and appears to sort keys by name

                string doc_to_sign;
                nlohmann::json serializer;
                serializer["contract_id"] = in.contract_id;
                serializer["contract_creator"] = contract_r.value().contract_creator_verifying_key_PEM;
                serializer["enclaves_info"] = contract_r.value().enclave_info;
                serializer["provisioning_services"] = contract_r.value().provisioning_service_ids;
                doc_to_sign = serializer.dump();

                auto signature = TPHandlerRegistry ::sign_document(doc_to_sign);

                return make_success(Get_contract_provisioning_info::Out{contract_r.value().contract_creator_verifying_key_PEM,
                            contract_r.value().provisioning_service_ids,
                            contract_r.value().enclave_info, signature});
            }
            return make_error(HTTP_STATUS_BAD_REQUEST, "Contract not found");

        };

        //======================================================================================================
        // get current state info handler implementation
        auto get_contract_info = [this](kv::Tx& tx, const nlohmann::json& params) {

            const auto in = params.get<Get_current_state_info::In>();
            auto view = tx.get_view(contracttable);
            auto contract_r = view->get_globally_committed(in.contract_id);

            if (! contract_r.has_value())
            {
                return make_error(HTTP_STATUS_BAD_REQUEST, "Contract not found");
            }

            if (ledger_signer_local == NULL) {
                auto signer_view = tx.get_view(signer);
                auto signer_global = signer_view->get_globally_committed("signer");
                if (signer_global.has_value()){
                    auto key_pair = signer_global.value();
                    auto privk_pem = tls::Pem(key_pair["privk"]);
                    ledger_signer_local = make_key_pair(privk_pem, nullb, false);
                }
                else {
                    return make_error(
                        HTTP_STATUS_BAD_REQUEST, "Unable to locate ledger authority for signing read rpcs");
                }
            }

            auto contract_code_hash = contract_r.value().contract_code_hash;
            auto encoded_code_hash = b64_from_raw(contract_code_hash.data(), contract_code_hash.size());
            auto creator_key = contract_r.value().contract_creator_verifying_key_PEM;

            string doc_to_sign = in.contract_id + creator_key + encoded_code_hash;
            auto signature = TPHandlerRegistry ::sign_document(doc_to_sign);

            return make_success(Get_contract_info::Out{creator_key, encoded_code_hash, signature});
        };

        //======================================================================================================
        // get current state info handler implementation
        auto get_current_state_info_for_contract = [this](kv::Tx& tx, const nlohmann::json& params) {

            const auto in = params.get<Get_current_state_info::In>();
            auto view = tx.get_view(contracttable);
            auto contract_r = view->get_globally_committed(in.contract_id);

            if (!contract_r.has_value())
            {
                return make_error(HTTP_STATUS_BAD_REQUEST, "Contract not found");
            }

            if(contract_r.value().is_active && contract_r.value().current_state_hash.size() == 0) {
                return make_error(HTTP_STATUS_BAD_REQUEST, "Contract not yet initialized");
            }

            if (ledger_signer_local == NULL) {
                auto signer_view = tx.get_view(signer);
                auto signer_global = signer_view->get_globally_committed("signer");
                if (signer_global.has_value()){
                    auto key_pair = signer_global.value();
                    auto privk_pem = tls::Pem(key_pair["privk"]);
                    ledger_signer_local = make_key_pair(privk_pem, nullb, false);
                }
                else {
                    return make_error(
                        HTTP_STATUS_BAD_REQUEST, "Unable to locate ledger authority for signing read rpcs");
                }
            }

            auto current_state_hash = contract_r.value().current_state_hash;
            auto encoded_state_hash = b64_from_raw(current_state_hash.data(), current_state_hash.size());
            string doc_to_sign = in.contract_id + encoded_state_hash;
            auto signature = TPHandlerRegistry ::sign_document(doc_to_sign);

            return make_success(Get_current_state_info::Out{encoded_state_hash, contract_r.value().is_active, signature});

        };

        //======================================================================================================
        // get state details handler implementation
        auto get_details_about_state = [this](kv::Tx& tx, const nlohmann::json& params) {

            const auto in = params.get<Get_state_details::In>();
            auto view = tx.get_view(ccltable);

            string key_for_get =  in.contract_id + string(in.state_hash.begin(), in.state_hash.end());

            auto ccl_r = view->get_globally_committed(key_for_get);

            if (!ccl_r.has_value())
            {
                return make_error(
                    HTTP_STATUS_BAD_REQUEST, "Unknown (contract_id, state_hash) pair");
            }

            nlohmann::json j = ccl_r.value().dependency_list;
            string dep_list_string = j.dump();

            if (ledger_signer_local == NULL) {
                auto signer_view = tx.get_view(signer);
                auto signer_global = signer_view->get_globally_committed("signer");
                if (signer_global.has_value()){
                    auto key_pair = signer_global.value();
                    auto privk_pem = tls::Pem(key_pair["privk"]);
                    ledger_signer_local = make_key_pair(privk_pem, nullb, false);
                }
                else {
                    return make_error(
                        HTTP_STATUS_BAD_REQUEST, "Unable to locate ledger authority for signing read rpcs");
                }
            }

            auto ccl_value = ccl_r.value();
            string encoded_psh;
            if(ccl_value.previous_state_hash.size()==0){ // to address the case when the current state is "init".
                encoded_psh="";                          // this used to work automatically with ccf 0.9, but with
            }                                            // ccf 0.11, the b64_from_raw fails for empty input
            else{
                encoded_psh = b64_from_raw(ccl_value.previous_state_hash.data(), ccl_value.previous_state_hash.size());
            }

            auto encoded_mh = b64_from_raw(ccl_value.message_hash.data(), ccl_value.message_hash.size());
            auto encoded_txnid = b64_from_raw(ccl_value.transaction_id.data(), ccl_value.transaction_id.size());

            string doc_to_sign;
            doc_to_sign += encoded_psh;
            doc_to_sign += encoded_mh;
            doc_to_sign += encoded_txnid;
            doc_to_sign += dep_list_string;
            auto signature = TPHandlerRegistry ::sign_document(doc_to_sign);

            return make_success(Get_state_details::Out{encoded_txnid, encoded_psh, encoded_mh, dep_list_string, signature});

        };

        install(GEN_SIGNING_KEY, json_adapter(gen_signing_key), Write);
        install(GET_LEDGER_KEY, json_adapter(get_ledger_key), Write);

        install(REGISTER_ENCLAVE, json_adapter(register_enclave), Write);
        install(REGISTER_CONTRACT, json_adapter(register_contract), Write);
        install(ADD_ENCLAVE_TO_CONTRACT, json_adapter(add_enclave), Write);
        install(INITIALIZE_CONTRACT_STATE, json_adapter(initialize_contract_state), Write);
        install(UPDATE_CONTRACT_STATE, json_adapter(update_contract_state), Write);

        //Change the following four to read type
        install(PingMe, json_adapter(ping), Read);
        install(VERIFY_ENCLAVE_REGISTRATION, json_adapter(verify_enclave), Read);
        install(GET_CONTRACT_PROVISIONING_INFO, json_adapter(get_contract_provisioning_info), Read);
        install(GET_CONTRACT_INFO, json_adapter(get_contract_info), Read);
        install(GET_CURRENT_STATE_INFO_FOR_CONTRACT, json_adapter(get_current_state_info_for_contract), Read);
        install(GET_DETAILS_ABOUT_STATE, json_adapter(get_details_about_state), Read);
    }

    // Constructor for the app class: Point to rpc handlers
    TransactionProcessor::TransactionProcessor(kv::Store& store) :
        UserRpcFrontend(store, tp_handlers),
        tp_handlers(store)
        {
           disable_request_storing();
        }


    // This the entry point to the application. Point to the app class
    std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    NetworkTables& nwt, ccfapp::AbstractNodeContext& context)
    {
        return make_shared<TransactionProcessor>(*nwt.tables);
    }

}
