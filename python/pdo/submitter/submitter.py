# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging

from sawtooth.helpers.pdo_connect import PdoClientConnectHelper
import pdo.common.crypto as crypto

logger = logging.getLogger(__name__)

####### internal functions######################################

def compute_pdo_signature(private_key, tx_signer_public_key, contract_code_hash, provisioning_service_ids_array):
    k = crypto.SIG_PrivateKey(private_key)
    message = tx_signer_public_key + contract_code_hash
    for s in provisioning_service_ids_array:
        message += s
    message_byte_array = bytes(message, 'ascii')
    signature = k.SignMessage(message_byte_array)
    encoded_signature = crypto.byte_array_to_base64(signature)
    logger.debug("signed message string:" + message)
    logger.debug("signature: %s", encoded_signature)
    return encoded_signature

def compute_pdo_add_enclave_signature(private_key, tx_signer_public_key, contract_id, enclave_info_quintuples_array):
    k = crypto.SIG_PrivateKey(private_key)
    #concatenate tx signer and contract id
    message = tx_signer_public_key + contract_id
    for s in enclave_info_quintuples_array:
        for t in s['provisioning_key_state_secret_pairs']:
            #concatenate each ps public key and signed secret
            message += t['pspk']
            message += t['encrypted_secret']
        #concatenate encrypted state encryption key
        message +=s['encrypted_state_encryption_key']
        #contatenate enclave's signature
        message +=s['signature']
    message_byte_array = bytes(message, 'ascii')
    signature = k.SignMessage(message_byte_array)
    encoded_signature = crypto.byte_array_to_base64(signature)
    logger.debug("signed message string:" + message)
    logger.debug("signature: %s", encoded_signature)
    return encoded_signature

def get_epid_pseudonym_from_proof_data(proof_data):
    pj = json.loads(proof_data)
    vj = json.loads(pj['verification_report'])
    return vj['epidPseudonym']

def compute_pdo_ccl_signature(
    private_key,
    enclave_id,
    enclave_signature,
    channel_id,
    contract_id,
    creator_public_key_pem,
    contract_code_hash,
    message_hash,
    current_state_hash,
    previous_state_hash,
    dependency_list):
    k = crypto.SIG_PrivateKey(private_key)
    message_byte_array = crypto.string_to_byte_array(enclave_id)
    message_byte_array += crypto.base64_to_byte_array(enclave_signature)
    message_byte_array += crypto.string_to_byte_array(channel_id)
    message_byte_array += crypto.string_to_byte_array(contract_id)
    message_byte_array += crypto.string_to_byte_array(creator_public_key_pem)
    message_byte_array += crypto.base64_to_byte_array(contract_code_hash)
    message_byte_array += crypto.base64_to_byte_array(message_hash)
    message_byte_array += crypto.base64_to_byte_array(current_state_hash)
    #in ccl initialize, previous state hash and dependencies are supposed to be empty
    if previous_state_hash:
        message_byte_array += crypto.base64_to_byte_array(previous_state_hash)
    for d in dependency_list:
        message_byte_array += crypto.string_to_byte_array(d.contract_id)
        message_byte_array += crypto.string_to_byte_array(d.state_hash)
    signature = k.SignMessage(message_byte_array)
    encoded_signature = crypto.byte_array_to_base64(signature)
    logger.debug("signed message string: " + crypto.byte_array_to_base64(message_byte_array))
    logger.debug("signed message hash: " + crypto.byte_array_to_hex(crypto.compute_message_hash(message_byte_array)))
    logger.debug("signature: %s", encoded_signature)
    return encoded_signature

################################################################

class JsonPayloadBuilder(object):
    @staticmethod
    def build_contract_registration_from_data(
        creator_priv_key,
        creator_pub_key,
        tx_signer_pub_key,
        contract_code_hash,
        provisioning_service_ids):
        jsonblob = dict()
        jsonblob['af'] = "pdo_contract_instance_registry"
        jsonblob['verb'] = "register"
        jsonblob['pdo_contract_creator_pem_key'] = creator_pub_key
        #NOTICE: the contract_id is included for testing purporses, otherwise the contract id must be empty (or inexistent)
        jsonblob['contract_id'] = ""
        jsonblob['contract_code_hash'] = contract_code_hash
        #add provisining services
        jsonblob['provisioning_service_ids'] = provisioning_service_ids
        jsonblob['pdo_signature'] = compute_pdo_signature(
            creator_priv_key,
            tx_signer_pub_key,
            contract_code_hash,
            provisioning_service_ids)
        return jsonblob

    @staticmethod
    def build_enclave_registration_from_data(
        verifying_key,
        encryption_key,
        proof_data,
        registration_block_context,
        organizational_info):
        jsonblob = dict()
        jsonblob['af'] = "pdo_contract_enclave_registry"
        jsonblob['verb'] = "register"
        jsonblob['verifying_key'] = verifying_key
        jsonblob['encryption_key'] = encryption_key
        jsonblob['proof_data'] = proof_data
        if proof_data:
            #MUST: enclave_persistent_id must be equal to the epid pseudonym
            jsonblob['enclave_persistent_id'] = get_epid_pseudonym_from_proof_data(proof_data)
        else:
            jsonblob['enclave_persistent_id'] = "ignored field, no proof data"
        jsonblob['registration_block_context'] = registration_block_context
        jsonblob['organizational_info'] = organizational_info
        return jsonblob

    @staticmethod
    def build_add_enclave_from_data(
        contract_creator_private_key_pem,
        tx_signer_public_key,
        contract_id,
        enclave_info_quintuples):
        jsonblob = dict()
        jsonblob['af'] = "pdo_contract_instance_registry"
        jsonblob['verb'] = "add-enclaves"
        jsonblob['contract_id'] = contract_id
        jsonblob['pdo_signature'] = compute_pdo_add_enclave_signature(
            contract_creator_private_key_pem,
            tx_signer_public_key,
            contract_id,
            #enclave_info_quintuples is an array of items (contract_id, enclave id, array of
            #   <PS public key-signed secret> pairs, encrypted state encryption key, enclave's signature)
            enclave_info_quintuples)
        jsonblob['enclaves_info'] = []
        for enclave_info in enclave_info_quintuples:
            #build single enclave info
            einfo_item = dict()
            einfo_item['contract_enclave_id'] = enclave_info['contract_enclave_id']
            einfo_item['enclaves_map'] = []
            i=0
            for pair in enclave_info['provisioning_key_state_secret_pairs']:
                triple = dict()
                triple['index'] = i
                triple['provisioning_service_public_key'] = pair['pspk']
                triple['provisioning_contract_state_secret'] = pair['encrypted_secret']
                einfo_item['enclaves_map'].append(triple)
                i = i+1
            einfo_item['encrypted_contract_state_encryption_key'] = enclave_info['encrypted_state_encryption_key']
            einfo_item['enclave_signature'] = enclave_info['signature']
            jsonblob['enclaves_info'].append(einfo_item)
        return jsonblob

    @staticmethod
    def build_ccl_transaction_from_data(
        contract_creator_private_pem_key,
        contract_creator_public_key_pem,
        verb,
        channel_id,
        contract_enclave_id,
        enclave_signature,
        contract_id,
        message_hash,
        current_state_hash,
        previous_state_hash,
        encrypted_state,
        dependency_list,
        contract_code_hash):
        jsonblob = dict()
        jsonblob['af'] = "ccl_contract"
        jsonblob['verb'] = verb
        jsonblob['channel_id'] = channel_id
        jsonblob['contract_enclave_id'] = contract_enclave_id
        jsonblob['contract_enclave_signature'] = enclave_signature
        if not contract_creator_private_pem_key: #no creator key, leave signature empty
            jsonblob['pdo_signature'] = ""
        else: #compute and insert the creator's signature
            jsonblob['pdo_signature'] = compute_pdo_ccl_signature(
                contract_creator_private_pem_key,
                contract_enclave_id,
                enclave_signature,
                channel_id,
                contract_id,
                contract_creator_public_key_pem,
                contract_code_hash,
                message_hash,
                current_state_hash,
                previous_state_hash,
                dependency_list)
        state_update = dict()
        state_update['contract_id'] = contract_id
        state_update['message_hash'] = message_hash
        state_update['current_state_hash'] = current_state_hash
        state_update['previous_state_hash'] = previous_state_hash
        state_update['encrypted_state'] = encrypted_state
        state_update['dependency_list'] = dependency_list
        jsonblob['state_update'] = state_update
        return jsonblob

class Submitter(object):
    def __init__(self, url=None, keyfile=None, key_str=None, auto_generate=False):
        self._url = url or 'http://localhost:8008'

        self._connect_helper = PdoClientConnectHelper(self._url, keyfile, key_str, auto_generate)

    def submit_json(self, json_input, address_family, **extra_params) :
        wait = extra_params.get('wait', 0.0)
        exception_type = extra_params.get('exception_type', Exception)
        verbose = extra_params.get('verbose', False)
        transaction_dependency_list = extra_params.get('transaction_dependency_list', None)

        json_payload = json.dumps(json_input)
        signature = self._connect_helper.\
            execute_json_transaction(
                json_payload,
                address_family,
                wait,
                exception_type,
                verbose,
                transaction_dependency_list=transaction_dependency_list)
        logger.debug("json: %s", json_payload)
        logger.debug("signature: %s", signature)
        return signature

    def submit_contract_registration_from_data(
            self,
            creator_priv_key,
            creator_pub_key,
            tx_signer_pub_key,
            contract_code_hash,
            provisioning_service_ids,
            **extra_params):
        json_input = JsonPayloadBuilder.build_contract_registration_from_data(
            creator_priv_key,
            creator_pub_key,
            tx_signer_pub_key,
            contract_code_hash,
            provisioning_service_ids)
        return self.submit_json(json_input, json_input['af'], **extra_params)

    def submit_enclave_registration_from_data(
            self,
            verifying_key,
            encryption_key,
            proof_data,
            registration_block_context,
            organizational_info,
            **extra_params):
        json_input = JsonPayloadBuilder.build_enclave_registration_from_data(
            verifying_key,
            encryption_key,
            proof_data,
            registration_block_context,
            organizational_info)
        return self.submit_json(json_input, json_input['af'], **extra_params)

    def submit_add_enclave_from_data(
            self,
            contract_creator_private_key_pem,
            tx_signer_public_key,
            contract_id,
            enclave_info_quintuples,
            **extra_params):
        json_input = JsonPayloadBuilder.build_add_enclave_from_data(
            contract_creator_private_key_pem,
            tx_signer_public_key,
            contract_id,
            enclave_info_quintuples)
        return self.submit_json(json_input, json_input['af'], **extra_params)

    def submit_ccl_initialize_from_data(
            self,
            contract_creator_private_pem_key,
            contract_creator_public_pem_key,
            channel_id,
            contract_enclave_id,
            enclave_signature,
            contract_id,
            message_hash,
            current_state_hash,
            encrypted_state,
            contract_code_hash,
            **extra_params):
        json_input = JsonPayloadBuilder.build_ccl_transaction_from_data(
            contract_creator_private_pem_key,
            contract_creator_public_pem_key,
            'initialize',
            channel_id,
            contract_enclave_id,
            enclave_signature,
            contract_id,
            message_hash,
            current_state_hash,
            "",     # previous_state_hash,
            encrypted_state,
            [],     # empty dependency_list
            contract_code_hash)     # contract code hash is necessary for the pdo signature
        return self.submit_json(json_input, json_input['af'], **extra_params)

    def submit_ccl_update_from_data(
            self,
            contract_creator_public_pem_key,
            channel_id,
            contract_enclave_id,
            enclave_signature,
            contract_id,
            message_hash,
            current_state_hash,
            previous_state_hash,
            encrypted_state,
            dependency_list,
            **extra_params):
        json_input = JsonPayloadBuilder.build_ccl_transaction_from_data(
            "",     #no creator private key, so no pdo signature included
            contract_creator_public_pem_key,
            'update',
            channel_id,
            contract_enclave_id,
            enclave_signature,
            contract_id,
            message_hash,
            current_state_hash,
            previous_state_hash,
            encrypted_state,
            dependency_list,
            "contract_code_hash is not relevant here")  #no contract hash because no creator's signature is required
        return self.submit_json(json_input, json_input['af'], **extra_params)
