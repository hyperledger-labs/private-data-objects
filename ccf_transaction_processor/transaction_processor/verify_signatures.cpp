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
using namespace crypto;
using namespace tls;

namespace ccfapp
{


    bool TPHandlerRegistry ::verify_sig_static(vector<uint8_t> signature, const tls::PublicKeyPtr & pubk_verifier, \
            const vector<uint8_t>& contents) {

        // verify & return true or false
        return pubk_verifier->verify(contents, signature);

    }

    bool TPHandlerRegistry ::verify_sig(vector<uint8_t> signature, const string & verifying_key, \
            const vector<uint8_t>& contents) {

        // format the verifying key as needed by CCF to create the verifier
        const auto public_key_pem = tls::Pem(CBuffer(verifying_key));
        auto pubk_verifier = tls::make_public_key(public_key_pem, true); // false means use mbed, true means use bitcoin
        return pubk_verifier->verify(contents, signature); // return true/false

    }

    bool TPHandlerRegistry ::verify_pdo_transaction_signature_register_enclave(const vector<uint8_t>& signature, const string & verifying_key,
        const EnclaveInfo & enclave_info){

            string message = verifying_key;
            message += enclave_info.verifying_key;
            message += enclave_info.encryption_key;
            message += enclave_info.proof_data;
            message += enclave_info.enclave_persistent_id;
            message += enclave_info.registration_block_context;
            message += enclave_info.organizational_info;

            vector<uint8_t> contents(message.begin(), message.end());

            return verify_sig(signature, verifying_key, contents);
    }

    bool TPHandlerRegistry ::verify_pdo_transaction_signature_register_contract(const vector<uint8_t>& signature, const string & verifying_key, \
        const vector<uint8_t> & contract_code_hash, const string & nonce, const vector<string> & provisioning_service_ids){


            vector<uint8_t> contents(verifying_key.begin(), verifying_key.end());
            contents.insert(contents.end(), contract_code_hash.begin(), contract_code_hash.end());

            string message;
            for(auto str: provisioning_service_ids) {
                message += str;
            }
            message+=nonce;
            vector<uint8_t> temp(message.begin(), message.end());

            contents.insert(contents.end(), temp.begin(), temp.end());

            return verify_sig(signature, verifying_key, contents);
    }

    bool TPHandlerRegistry ::verify_pdo_transaction_signature_add_enclave(const vector<uint8_t>& signature, const string & verifying_key, \
        const string & contract_id, const string &  enclave_info_json_string){

            string message = verifying_key;
            message += contract_id;
            message += enclave_info_json_string;

            vector<uint8_t> contents(message.begin(), message.end());

            return verify_sig(signature, verifying_key, contents);
    }

    bool TPHandlerRegistry ::verify_enclave_signature_add_enclave(const string& signature, const tls::PublicKeyPtr & pubk_verifier, \
        const string & contract_creator_key, const string & contract_id, const vector<ProvisioningKeysToSecretMap> & prov_key_maps, \
        const string & encrypted_state_encryption_key){

            string message = contract_id;
            message += contract_creator_key;
            for (auto prov :prov_key_maps ) {
                message += prov.pspk;
                message += prov.encrypted_secret;
            }

            vector<uint8_t> contents(message.begin(), message.end());
            vector<uint8_t> temp = raw_from_b64(encrypted_state_encryption_key);
            contents.insert(contents.end(), temp.begin(), temp.end());

           auto signature_byte_array = raw_from_b64(signature);

           //remove any trailing zeros (null characters) in the signature array
           //this seems to be necessary for verifying this sign
            while(true){
                if (signature_byte_array.back() == 0){
                    signature_byte_array.pop_back();
                }
                else{
                    break;
                }
            }

            return verify_sig_static(signature_byte_array, pubk_verifier, contents);
    }


    bool TPHandlerRegistry ::verify_pdo_transaction_signature_update_contract_state(const vector<uint8_t>& signature, \
        const string & verifying_key, const string & contract_enclave_id, const vector<uint8_t>& contract_enclave_signature, \
        const string & state_update_info) {

            string message = verifying_key;
            message += contract_enclave_id;

            vector<uint8_t> contents(message.begin(), message.end());
            contents.insert(contents.end(), contract_enclave_signature.begin(), contract_enclave_signature.end());

            vector<uint8_t> temp(state_update_info.begin(), state_update_info.end());
            contents.insert(contents.end(), temp.begin(), temp.end());

            return verify_sig(signature, verifying_key, contents);
    }

    bool TPHandlerRegistry ::verify_enclave_signature_update_contract_state(const vector<uint8_t>& signature, \
        const tls::PublicKeyPtr & pubk_verifier, const vector<uint8_t> & nonce, const string & contract_creator_verifying_key_PEM, \
        const vector<uint8_t> & contract_code_hash, const StateUpdateInfo & state_update_info) {

            // Get the hash of the nonce first
            Sha256Hash h;
            Sha256Hash::evercrypt_sha256({nonce}, h.h.data());
            vector<uint8_t> hash(h.h.data(), h.h.data() + 32);
            string message = b64_from_raw(hash.data(), hash.size());

            message += state_update_info.contract_id;
            message += contract_creator_verifying_key_PEM;
            vector<uint8_t> contents(message.begin(), message.end());

            contents.insert(contents.end(), contract_code_hash.begin(), contract_code_hash.end());
            contents.insert(contents.end(), state_update_info.message_hash.begin(), state_update_info.message_hash.end());
            contents.insert(contents.end(), state_update_info.current_state_hash.begin(), state_update_info.current_state_hash.end());
            contents.insert(contents.end(), state_update_info.previous_state_hash.begin(), state_update_info.previous_state_hash.end());

            message.clear();

            for (auto dep: state_update_info.dependency_list) {
                message += dep.contract_id;
                message += dep.state_hash_for_sign;
            }

            contents.insert(contents.end(), message.begin(), message.end());

            return verify_sig_static(signature, pubk_verifier, contents);
    }

}
