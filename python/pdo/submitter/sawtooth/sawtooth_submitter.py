# Copyright 2020 Intel Corporation
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

from pdo.submitter.sawtooth.helpers.pdo_connect import PdoClientConnectHelper, PdoRegistryHelper
import pdo.common.crypto as crypto
import pdo.common.keys as keys
import pdo.submitter.submitter as sub

logger = logging.getLogger(__name__)

class SawtoothSubmitter(sub.Submitter):
    def __init__(self, ledger_config, *args, **kwargs):
        super().__init__(ledger_config, *args, **kwargs)

        # Sawtooth Specific Parameters.
        self.wait = ledger_config.get('wait', 30.0) # submitter will wait 30 seconds to hear back from Sawtooth
                                    # If no response, client to check back with Sawtooth about the status
        #Sawtooth read helper
        self.read_helper = PdoRegistryHelper(self.url) #registry helper for read transactions

# -----------------------------------------------------------------
    def submit_json(self, json_input, address_family, **extra_params) :

        # Get the write connect_helper. This cannot be attached to the class instance, since
        # the sawtooth header signing key must be unique for each transaction.
        # Previously, each class instance was used only for a single transaction,
        # so this was not a problem. The current implementation permits an instance to be reused

        key_str = extra_params.get('key_str', None) # this is the header signing key
        if key_str is None:
            txn_keys = keys.TransactionKeys()
            key_str = txn_keys.txn_private

        transaction_dependency_list = extra_params.get('transaction_dependency_list', None)

        # Sawtooth connector supports a few extra parameters. We shall fix these in PDO
        keyfile = None
        auto_generate = False
        exception_type = Exception
        verbose = False

        connect_helper = PdoClientConnectHelper(self.url, keyfile, key_str, auto_generate)

        json_payload = json.dumps(json_input)
        signature = connect_helper.\
            execute_json_transaction(
                json_payload,
                address_family,
                self.wait,
                exception_type,
                verbose,
                transaction_dependency_list=transaction_dependency_list)
        logger.debug("json: %s", json_payload)
        logger.debug("signature: %s", signature)

        return signature

# -----------------------------------------------------------------
    def register_encalve(self,
        enclave_verifying_key,
        enclave_encryption_key,
        proof_data,
        registration_block_context,
        organizational_info,
        **extra_params):

        json_input = JsonPayloadBuilder.build_enclave_registration_from_data(
            enclave_verifying_key,
            enclave_encryption_key,
            proof_data,
            registration_block_context,
            organizational_info)

        extra_params['key_str'] = self.pdo_signer.txn_private # for enclave registration, the eservice keys
                                # are used to sign the Sawtooth header
        return self.submit_json(json_input, json_input['af'], **extra_params)

# -----------------------------------------------------------------
    def register_contract(self,
        contract_code_hash,
        provisioning_service_ids,
        **extra_params):

        txn_keys = keys.TransactionKeys()

        json_input = JsonPayloadBuilder.build_contract_registration_from_data(
            self.pdo_signer.signing_key,
            self.pdo_signer.verifying_key,
            txn_keys.txn_public,
            crypto.byte_array_to_base64(contract_code_hash),
            provisioning_service_ids)

        extra_params['key_str'] = txn_keys.txn_private

        return self.submit_json(json_input, json_input['af'], **extra_params)

# -----------------------------------------------------------------
    def add_enclave_to_contract(self,
        contract_id,
        enclave_info_quintuples,
        **extra_params):

        txn_keys = keys.TransactionKeys()

        json_input = JsonPayloadBuilder.build_add_enclave_from_data(
            self.pdo_signer.signing_key,
            txn_keys.txn_public,
            contract_id,
            enclave_info_quintuples)

        extra_params['key_str'] = txn_keys.txn_private

        return self.submit_json(json_input, json_input['af'], **extra_params)

# -----------------------------------------------------------------
    def ccl_initialize(self,
        channel_keys,
        contract_enclave_id,
        enclave_signature,
        contract_id,
        message_hash,
        current_state_hash,
        contract_code_hash,
        **extra_params):

        json_input = JsonPayloadBuilder.build_ccl_transaction_from_data(
            self.pdo_signer.signing_key,
            self.pdo_signer.verifying_key,
            'initialize',
            channel_keys.txn_public,
            contract_enclave_id,
            enclave_signature,
            contract_id,
            crypto.byte_array_to_base64(message_hash),
            crypto.byte_array_to_base64(current_state_hash),
            "",     # previous_state_hash,
            "",     # encyrpted root block. No longer stored in Sawtooth
            [],     # empty dependency_list
            crypto.byte_array_to_base64(contract_code_hash))
                            # contract code hash is necessary for the pdo signature

        extra_params['key_str'] = channel_keys.txn_private

        return self.submit_json(json_input, json_input['af'], **extra_params)

# -----------------------------------------------------------------
    def ccl_update(self,
        channel_keys,
        contract_enclave_id,
        enclave_signature,
        contract_id,
        message_hash,
        current_state_hash,
        previous_state_hash,
        dependency_list,
        **extra_params):

        json_input = JsonPayloadBuilder.build_ccl_transaction_from_data(
            "",     #no creator private key, so no pdo signature included
            "",     #no need for creator public key for update txns
            'update',
            channel_keys.txn_public,
            contract_enclave_id,
            enclave_signature,
            contract_id,
            crypto.byte_array_to_base64(message_hash),
            crypto.byte_array_to_base64(current_state_hash),
            crypto.byte_array_to_base64(previous_state_hash),
            "",     #encyrpted root block. No longer stored in Sawtooth
            dependency_list,
            "")  #no contract hash because there is no pdo sign

        extra_params['key_str'] = channel_keys.txn_private

        return self.submit_json(json_input, json_input['af'], **extra_params)

# -----------------------------------------------------------------
    def get_enclave_info(self,
        enclave_id):

        return self.read_helper.get_enclave_dict(enclave_id)

# -----------------------------------------------------------------
    def get_contract_info(self,
        contract_id):

        return self.read_helper.get_contract_dict(contract_id)

# -----------------------------------------------------------------
    def get_current_state_hash(self,
        contract_id):

        ccl_info = self.read_helper.get_ccl_info_dict(contract_id)

        state_info = dict()
        state_info['state_hash'] = ccl_info['current_state']['state_hash']
        state_info['is_active'] = ccl_info['is_active']

        return state_info

# -----------------------------------------------------------------
    def get_state_details(self,
        contract_id,
        state_hash):

        ccl_info = self.read_helper.get_ccl_state_dict(contract_id, state_hash)

        state_details = dict()
        state_details['transaction_id'] = ccl_info['transaction_id']
        state_details.update(ccl_info['state_update'])

        return state_details


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

# -----------------------------------------------------------------
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

# -----------------------------------------------------------------
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

# -----------------------------------------------------------------
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
            jsonblob['enclave_persistent_id'] = sub.get_epid_pseudonym_from_proof_data(proof_data)
        else:
            jsonblob['enclave_persistent_id'] = "ignored field, no proof data"
        jsonblob['registration_block_context'] = registration_block_context
        jsonblob['organizational_info'] = organizational_info
        return jsonblob

# -----------------------------------------------------------------
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

# -----------------------------------------------------------------
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