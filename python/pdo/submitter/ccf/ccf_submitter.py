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

import http
import json
import logging
import time
import os
import sys

from ccf.clients import CCFClient
from urllib.parse import urlparse

import pdo.common.crypto as crypto
import pdo.common.keys as keys
import pdo.submitter.submitter as sub

logger = logging.getLogger(__name__)

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class CCFClientWrapper(CCFClient) :
    #CCF reads return global commits, while writes return after local commit.
    #There is a small time delay before local commit appears globally.
    #To accomodate the possibility that a read might be invoked immediately following a write,
    #each read is re-attempted 3 (at most) times if there is a failure. The following array
    #describes the wait time before the ith read
    read_backoff_duration = [0.25, 0.5, 1, 2, 3]

    # -----------------------------------------------------------------
    def __init__(self, host, port) :

        #ensure that ccf keys are present
        ccf_key_dir = os.environ.get("PDO_LEDGER_KEY_ROOT")
        ca_file = os.path.join(ccf_key_dir, "networkcert.pem")

        if os.path.exists(ca_file) is False :
            logger.error("Cannot locate CCF network certificate. Aborting transaction")
            raise Exception("Cannot locate CCF network certificate. Aborting transaction")

        # create the request client
        logger.debug("Creating the CCF Request client")
        super().__init__(host, port, ca_file)

        #get CCF verifying key (specific to PDO TP)
        try:
            ledger_response = self.submit_read_request("get_ledger_verifying_key", dict())
            self.ccf_verifying_key = ledger_response['verifying_key']
            self.__ccf_signature_verifyer__ = crypto.SIG_PublicKey(self.ccf_verifying_key)
        except Exception as e:
            logger.exception("Unable to get ledger verifying key")
            raise e

    # -----------------------------------------------------------------
    def submit_read_request(self, tx_method, tx_params) :
        for wait in self.read_backoff_duration :
            #if read fails due to lack of global commit, response.status_code will not be OK
            response = self.submit_rpc(tx_method, tx_params)
            if response.status_code == http.HTTPStatus.OK:
                return response.body.json()

            logger.debug('ccf read request failed ({}); waiting {} for next attempt'.format(response.status_code, wait))
            time.sleep(wait)

        #read failed even after retries
        raise Exception("read request failed after multiple retries for tx_method {}".format(str(tx_method)))

    # -----------------------------------------------------------------
    def submit_rpc(self, tx_method, tx_params) :
        try:
            return self.post('/app/' + tx_method, body = tx_params, log_capture =[])
            # setting log_capture to [] prevents logs being flushed to screen by CCFClient object
        except Exception as e:
            logger.exception("Error while submitting transaction to CCF")
            raise e

    # -----------------------------------------------------------------
    def verify_ledger_signature(self, message, signature):
        """ Verify ledger signature. sign is base64 encoded. document is a string"""
        message_byte_array = bytes(message, 'ascii')
        decoded_signature = crypto.base64_to_byte_array(signature)
        result = self.__ccf_signature_verifyer__.VerifySignature(message_byte_array, decoded_signature)
        if result < 0 :
            raise Exception('malformed signature')

        return result

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class CCFSubmitter(sub.Submitter):

    # Ledger submitter used by PDO Clients when CCF based PDO TP is used.
    # this is a cache of connections to ledger servers, the cache
    # is not emptied when clients leave since there is no particular
    # need to disconnect explicitly, the cache is keyed on the host:port
    # end point
    ccf_client_cache = {}

    # -----------------------------------------------------------------
    def __init__(self, ledger_config, *args, **kwargs):
        super().__init__(ledger_config, *args, **kwargs)

        try:
            parsed_url = urlparse(self.url)
            self.host, port = parsed_url.netloc.split(':')
            self.port = int(port)
            self.endpoint = "{0}:{1}".format(self.host, self.port)
        except Exception as e:
            raise Exception("Unable to parse CCF ledger URL; must be of the form http://ip:port : %s", str(e))

        if self.endpoint in CCFSubmitter.ccf_client_cache :
            self.ccf_client = CCFSubmitter.ccf_client_cache[self.endpoint]
        else :
            self.ccf_client = CCFClientWrapper(self.host, self.port)
            CCFSubmitter.ccf_client_cache[self.endpoint] = self.ccf_client

    # -----------------------------------------------------------------
    def register_encalve(self,
        enclave_verifying_key,
        enclave_encryption_key,
        proof_data,
        registration_block_context,
        organizational_info,
        **extra_params):

        tx_method = "register_enclave"

        # tx_params as dict, will be converted to json the by the ccf client
        tx_params = PayloadBuilder.build_enclave_registration_from_data(
            enclave_verifying_key,
            enclave_encryption_key,
            proof_data,
            registration_block_context,
            organizational_info,
            self.pdo_signer)

        try:
            response = self.ccf_client.submit_rpc(tx_method, tx_params)
            if (response.status_code == http.HTTPStatus.OK) and (response.body.json() is True):
                # reponse body will be "True" for enclave registration transaction
                return tx_params['signature'] #PDO expects the submitter to return the transaction signature
            else:
                raise Exception(response.body.json())
        except Exception as e:
            logger.info('Register enclave TXN failed: {}'.format(str(e)))
            raise

# -----------------------------------------------------------------
    def register_contract(self,
        contract_code_hash,
        provisioning_service_ids,
        **extra_params):

        tx_method = "register_contract"

        tx_params = PayloadBuilder.build_contract_registration_from_data(
            self.pdo_signer,
            contract_code_hash,
            provisioning_service_ids
            )

        try:
            response = self.ccf_client.submit_rpc(tx_method, tx_params)
            if (response.status_code == http.HTTPStatus.OK) and (response.body.json() is True):
                # reponse body will be "True" for enclave registration transaction
                return crypto.byte_array_to_hex(tx_params['signature'])
            else:
                raise Exception(response.body.json())
        except Exception as e:
            logger.info('Register contract TXN failed: {}'.format(str(e)))
            raise

# -----------------------------------------------------------------
    def add_enclave_to_contract(self,
        contract_id,
        enclave_info_quintuples,
        **extra_params):

        tx_method = "add_enclave_to_contract"

        tx_params = PayloadBuilder.build_add_enclave_to_contract_from_data(
            self.pdo_signer,
            contract_id,
            enclave_info_quintuples
            )

        try:
            response = self.ccf_client.submit_rpc(tx_method, tx_params)
            if (response.status_code == http.HTTPStatus.OK) and (response.body.json() is True):
                # reponse body will be "True" for enclave registration transaction
                return tx_params['signature'] #PDO expects the submitter to return the transaction signature
            else:
                raise Exception(response.body.json())
        except Exception as e:
            logger.info('Add Enclave TXN failed: {}'.format(str(e)))
            raise

# -----------------------------------------------------------------
    def ccl_initialize(self,
        channel_keys,
        contract_enclave_id,
        enclave_signature,
        contract_id,
        contract_code_hash,               # not used by CCF
        message_hash,
        initial_state_hash,
        contract_metadata_hash,
        **extra_params):

        tx_method = "ccl_initialize"

        tx_params = PayloadBuilder.build_initialize_contract_state_transaction_from_data(
            channel_keys,
            contract_enclave_id,
            crypto.base64_to_byte_array(enclave_signature),
            contract_id,
            message_hash,
            initial_state_hash,
            contract_metadata_hash,
            self.pdo_signer.signing_key
            )
        try:
            response = self.ccf_client.submit_rpc(tx_method, tx_params)
            if (response.status_code == http.HTTPStatus.OK) and (response.body.json() is True):
                # reponse body will be "True" for enclave registration transaction
                return tx_params['nonce']
            else:
                raise Exception(response.body.json())
        except Exception as e:
            logger.info('CCL initialize TXN failed: {}'.format(str(e)))
            raise

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

        tx_method = "ccl_update"

        dependencies = []
        for dependency in dependency_list :
            temp = dict()
            temp['contract_id'] = dependency['contract_id']
            temp['state_hash'] = crypto.base64_to_byte_array(dependency['state_hash'])
            temp['state_hash_for_sign'] = dependency['state_hash']
            dependencies.append(temp)

        tx_params = PayloadBuilder.build_update_contract_state_transaction_from_data(
            channel_keys,
            contract_enclave_id,
            crypto.base64_to_byte_array(enclave_signature),
            contract_id,
            current_state_hash,
            previous_state_hash,
            message_hash,
            dependencies
            )

        try:
            response = self.ccf_client.submit_rpc(tx_method, tx_params)
            if (response.status_code == http.HTTPStatus.OK) and (response.body.json() is True):
                  # reponse body will be "True" for enclave registration transaction
                return tx_params['nonce']
            else:
                raise Exception(response.body.json())
        except Exception as e:
            logger.info('CCL update TXN failed: {}'.format(str(e)))
            raise

# -----------------------------------------------------------------
    def get_enclave_info(self,
        enclave_id):

        tx_method = "verify_enclave_registration"
        tx_params = PayloadBuilder.build_verify_enclave_from_data(enclave_id)

        enclave_info = self.ccf_client.submit_read_request(tx_method, tx_params)

        # verify ccf signature
        message = enclave_info["verifying_key"]
        message+= enclave_info["encryption_key"]
        message+= enclave_info["proof_data"]
        message+= enclave_info["last_registration_block_context"]
        message+= enclave_info["owner_id"]

        if not self.ccf_client.verify_ledger_signature(message, enclave_info["signature"]):
            raise Exception("Invalid signature on Get Enclave Info from CCF Ledger")

        return enclave_info

# -----------------------------------------------------------------
    def get_ledger_info(self) :
        return self.ccf_client.ccf_verifying_key

# -----------------------------------------------------------------
    def get_contract_info(self,
        contract_id):

        tx_method = "get_contract_info"
        tx_params = PayloadBuilder.build_get_contract_info_from_data(contract_id)

        contract_info = self.ccf_client.submit_read_request(tx_method, tx_params)

        # verify ccf signature
        message = contract_id
        message += contract_info["pdo_contract_creator_pem_key"]
        message += contract_info["contract_code_hash"]
        message += contract_info["metadata_hash"]

        if not self.ccf_client.verify_ledger_signature(message, contract_info["signature"]):
            raise Exception("Invalid signature on Get Contract Info from CCF Ledger")

        return contract_info

# -----------------------------------------------------------------
    def get_contract_provisioning_info(self,
        contract_id):

        tx_method = "get_contract_provisioning_info"
        tx_params = PayloadBuilder.build_verify_contract_registration_from_data(contract_id)

        contract_info = self.ccf_client.submit_read_request(tx_method, tx_params)

        # verify ccf signature
        bundle = {}
        bundle["contract_id"] = contract_id
        bundle["contract_creator"] = contract_info["pdo_contract_creator_pem_key"]
        bundle["enclaves_info"] = contract_info["enclaves_info"]
        bundle["provisioning_services"] = contract_info["provisioning_service_ids"]
        message = json.dumps(bundle, sort_keys=True, separators=(',', ':'))

        if not self.ccf_client.verify_ledger_signature(message, contract_info["signature"]):
            raise Exception("Invalid signature on Get Contract Info from CCF Ledger")

        return contract_info

# -----------------------------------------------------------------
    def get_current_state_hash(self,
        contract_id):

        tx_method = "get_current_state_info_for_contract"
        tx_params = PayloadBuilder.build_get_current_state_info_for_contract_from_data(contract_id)

        state_info = self.ccf_client.submit_read_request(tx_method, tx_params)

         # verify ccf signature
        message = contract_id + state_info["state_hash"]

        if not self.ccf_client.verify_ledger_signature(message, state_info["signature"]):
            raise Exception("Invalid signature on Get Current State Hash from CCF Ledger")

        return state_info

# -----------------------------------------------------------------
    def get_state_details(self,
        contract_id,
        state_hash):

        tx_method = "get_details_about_state"
        tx_params = PayloadBuilder.build_get_details_about_state_from_data(
            contract_id,
            crypto.base64_to_byte_array(state_hash))

        state_details = self.ccf_client.submit_read_request(tx_method, tx_params)

        # verify ccf signature
        message = state_details["previous_state_hash"]
        message+= state_details["message_hash"]
        message+= state_details["transaction_id"]
        message+= state_details["dependency_list"]

        if not self.ccf_client.verify_ledger_signature(message, state_details["signature"]):
            raise Exception("Invalid signature on Get State Details from CCF Ledger")

        return state_details

# -----------------------------------------------------------------
# Paylaod signature compute fucntions
# -----------------------------------------------------------------
def compute_pdo_signature_enclave_registration(
        signer,
        verifying_key,
        encryption_key,
        proof_data,
        enclave_persistent_id,
        registration_block_context,
        organizational_info) :

    message = signer.verifying_key
    message += verifying_key
    message += encryption_key
    message += proof_data
    message += enclave_persistent_id
    message += registration_block_context
    message += organizational_info

    return signer.sign(crypto.string_to_byte_array(message), encoding='raw')

# -----------------------------------------------------------------
def compute_pdo_signature_contract_registration(
        signing_key,
        verifying_key,
        contract_code_hash,
        provisioning_service_ids_array,
        nonce) :

    signer = keys.ServiceKeys(crypto.SIG_PrivateKey(signing_key))

    message = crypto.string_to_byte_array(verifying_key) + contract_code_hash
    for s in provisioning_service_ids_array:
        message += crypto.string_to_byte_array(s)
    message += crypto.string_to_byte_array(nonce)

    return signer.sign(message, encoding='raw')

# -----------------------------------------------------------------
def compute_pdo_add_enclave_signature(signing_key, verifying_key, contract_id, enclave_info_json_string):
    signer = keys.ServiceKeys(crypto.SIG_PrivateKey(signing_key))

    message = verifying_key + contract_id
    message+= enclave_info_json_string

    return signer.sign(message, encoding='raw')

# -----------------------------------------------------------------
def compute_creator_initialize_state_signature(
    creator_signing_key,
    contract_enclave_signature) :

    signer = keys.ServiceKeys(crypto.SIG_PrivateKey(creator_signing_key))
    return signer.sign(contract_enclave_signature, encoding='raw')

################################################################
class PayloadBuilder(object):

    @staticmethod
    def build_enclave_registration_from_data(
        verifying_key,
        encryption_key,
        proof_data,
        registration_block_context,
        organizational_info,
        txn_signer):
        payloadblob = dict()
        payloadblob['verifying_key'] = verifying_key
        payloadblob['encryption_key'] = encryption_key
        payloadblob['proof_data'] = proof_data
        if proof_data:
            payloadblob['enclave_persistent_id'] = sub.get_epid_pseudonym_from_proof_data(proof_data)
        else:
            payloadblob['enclave_persistent_id'] = "ignored field, no proof data"
        payloadblob['registration_block_context'] = registration_block_context
        payloadblob['organizational_info'] = organizational_info
        payloadblob['EHS_verifying_key'] = txn_signer.verifying_key

        #serialize the payload, sign it, and attach the json_payload and signature
        payloadblob['signature'] = compute_pdo_signature_enclave_registration(txn_signer, \
            verifying_key, encryption_key, proof_data, payloadblob['enclave_persistent_id'], \
            registration_block_context, organizational_info)

        return payloadblob

# -----------------------------------------------------------------
    @staticmethod
    def build_verify_enclave_from_data(enclave_id):
        payloadblob = dict()
        payloadblob['enclave_id'] = enclave_id
        # there is no need to sign these verification transactions
        return payloadblob

# -----------------------------------------------------------------
    @staticmethod
    def build_verify_contract_registration_from_data(contract_id):
        payloadblob = dict()
        payloadblob['contract_id'] = contract_id
        # there is no need to sign these verification transactions
        return payloadblob

# -----------------------------------------------------------------
    @staticmethod
    def build_get_contract_info_from_data(contract_id):
        payloadblob = dict()
        payloadblob['contract_id'] = contract_id
        # there is no need to sign these verification transactions
        return payloadblob

# -----------------------------------------------------------------
    @staticmethod
    def build_get_current_state_info_for_contract_from_data(contract_id):
        payloadblob = dict()
        payloadblob['contract_id'] = contract_id
        return payloadblob

# -----------------------------------------------------------------
    @staticmethod
    def build_get_details_about_state_from_data(contract_id, state_hash):
        payloadblob = dict()
        payloadblob['contract_id'] = contract_id
        payloadblob['state_hash'] = state_hash
        return payloadblob

# -----------------------------------------------------------------
    @staticmethod
    def build_contract_registration_from_data(
        contract_creator_keys,
        contract_code_hash,
        provisioning_service_ids):
        payloadblob = dict()
        payloadblob['contract_code_hash'] = contract_code_hash
        payloadblob['provisioning_service_ids'] = provisioning_service_ids
        payloadblob['contract_creator_verifying_key_PEM'] = contract_creator_keys.verifying_key

        # sign the payload after adding a nonce
        nonce = time.time().hex()
        payloadblob['nonce'] = nonce
        payloadblob['signature'] = compute_pdo_signature_contract_registration(contract_creator_keys.signing_key,
                contract_creator_keys.verifying_key, contract_code_hash, provisioning_service_ids, nonce)
        payloadblob['contract_id'] = \
            crypto.byte_array_to_base64(crypto.compute_message_hash(payloadblob['signature']))

        return payloadblob

# -----------------------------------------------------------------
    @staticmethod
    def build_add_enclave_to_contract_from_data(
        contract_creator_keys,
        contract_id,
        enclave_info_quintuples):
        payloadblob = dict()
        payloadblob['contract_id'] = contract_id
        payloadblob['enclave_info'] = json.dumps(enclave_info_quintuples, sort_keys=True)

        # sign the payload after adding a nonce
        payloadblob['signature'] = compute_pdo_add_enclave_signature(contract_creator_keys.signing_key,
                contract_creator_keys.verifying_key, contract_id, payloadblob['enclave_info'])

        return payloadblob

# -----------------------------------------------------------------
    @staticmethod
    def build_initialize_contract_state_transaction_from_data(
        nonce,
        contract_enclave_id,
        contract_enclave_signature,
        contract_id,
        message_hash,
        initial_state_hash,
        contract_metadata_hash,
        creator_signing_key
        ):

        payloadblob = dict()
        payloadblob['contract_id'] = contract_id
        payloadblob['initial_state_hash'] = initial_state_hash
        payloadblob['message_hash'] = message_hash
        payloadblob['metadata_hash'] = contract_metadata_hash
        payloadblob['contract_enclave_id'] = contract_enclave_id
        payloadblob['contract_enclave_signature'] = contract_enclave_signature
        payloadblob['creator_signature'] = compute_creator_initialize_state_signature(
            creator_signing_key, contract_enclave_signature)

        payloadblob['nonce'] = nonce
        return payloadblob

# -----------------------------------------------------------------
    @staticmethod
    def build_update_contract_state_transaction_from_data(
        nonce,
        contract_enclave_id,
        contract_enclave_signature,
        contract_id,
        current_state_hash,
        previous_state_hash,
        message_hash,
        dependency_list
        ):

        payloadblob = dict()
        payloadblob['contract_enclave_id'] = contract_enclave_id
        payloadblob['contract_enclave_signature'] = contract_enclave_signature

        state_update_info = dict()
        state_update_info['contract_id'] = contract_id
        state_update_info['current_state_hash'] = current_state_hash
        state_update_info['previous_state_hash'] = previous_state_hash
        state_update_info['message_hash'] = message_hash
        state_update_info['dependency_list'] = dependency_list
        state_update_info_string = json.dumps(state_update_info, sort_keys=True)

        payloadblob['state_update_info'] = state_update_info_string
        payloadblob['nonce'] = nonce

        return payloadblob
