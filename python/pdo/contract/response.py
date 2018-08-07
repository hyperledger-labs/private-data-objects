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
import os
import json

import pdo.common.crypto as crypto
import pdo.common.keys as keys

from pdo.submitter.submitter import Submitter
from pdo.contract.state import ContractState
from sawtooth.helpers.pdo_connect import PdoRegistryHelper

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class Dependencies(object) :

    """
    Class for mapping contract state commits to the corresponding
    ledger transaction. This class facilitates efficient assignment
    of dependencies in PDO transactions.
    """

    ## -------------------------------------------------------
    def __init__(self) :
        self.__depcache = {}

    ## -------------------------------------------------------
    def __key(self, contractid, statehash) :
        return str(contractid) + '$' + str(statehash)

    ## -------------------------------------------------------
    def __set(self, contractid, statehash, txnid) :
        self.__depcache[self.__key(contractid, statehash)] = txnid

    ## -------------------------------------------------------
    def __get(self, contractid, statehash) :
        k = self.__key(contractid, statehash)
        return self.__depcache.get(k)

    ## -------------------------------------------------------
    def FindDependency(self, ledger_config, contractid, statehash) :
        logger.debug('find dependency for %s, %s', contractid, statehash)

        txnid = self.__get(contractid, statehash)
        if txnid :
            return txnid

        # no information about this update locally, so go to the
        # ledger to retrieve it
        client = PdoRegistryHelper(ledger_config['LedgerURL'])

        try :
            # this is not very efficient since it pulls all of the state
            # down with the txnid
            contract_state_info = client.get_ccl_state_dict(contractid, statehash)
            txnid = contract_state_info['transaction_id']
            self.__set(contractid, statehash, txnid)
            return txnid
        except Exception as e :
            logger.info('failed to retrieve the transaction: %s', str(e))

        logger.info('unable to find dependency for %s:%s', contractid, statehash)
        return None

    ## -------------------------------------------------------
    def SaveDependency(self, contractid, statehash, txnid) :
        self.__set(contractid, statehash, txnid)


transaction_dependencies = Dependencies()

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ContractResponse(object) :
    """
    Class for managing the contract operation response from an enclave service
    """

    # -------------------------------------------------------
    def __init__(self, request, response) :
        """
        Initialize a contract response object

        :param request: the ContractRequest object corresponding to the response
        :param response: diction containing the response from the enclave
        """
        self.status = response['Status']
        self.result = response['Result']
        self.state_changed = response['StateChanged']

        if self.status and self.state_changed :
            self.signature = response['Signature']
            self.encrypted_state = response['State']

            # we have another mismatch between the field names in the enclave
            # and the field names expected in the transaction; this needs to
            # be fixed at some point
            self.dependencies = []
            for dependency in response['Dependencies'] :
                contract_id = dependency['ContractID']
                state_hash = dependency['StateHash']
                self.dependencies.append({'contract_id' : contract_id, 'state_hash' : state_hash})

            # save the information we will need for the transaction
            self.channel_keys = request.channel_keys
            self.contract_id = request.contract_id
            self.creator_id = request.creator_id
            self.code_hash = request.contract_code.compute_hash()
            self.message_hash = request.message.compute_hash()
            self.new_state_hash = ContractState.compute_hash(self.encrypted_state)
            self.originator_keys = request.originator_keys
            self.enclave_service = request.enclave_service

            self.old_state_hash = ()
            if request.operation != 'initialize' :
                self.old_state_hash = ContractState.compute_hash(request.contract_state.encrypted_state)

            if not self.__verify_enclave_signature(request.enclave_keys) :
                raise Exception('failed to verify enclave signature')

    # -------------------------------------------------------
    def __verify_enclave_signature(self, enclave_keys) :
        """verify the signature of the response
        """
        message = self.__serialize_for_signing()
        return enclave_keys.verify(message, self.signature, encoding = 'b64')

    # -------------------------------------------------------
    def __serialize_for_signing(self) :
        """serialize the response for enclave signature verification"""

        message = crypto.string_to_byte_array(self.channel_keys.txn_public)
        message += crypto.string_to_byte_array(self.contract_id)
        message += crypto.string_to_byte_array(self.creator_id)

        message += self.code_hash
        message += self.message_hash
        message += self.new_state_hash
        message += self.old_state_hash

        for dependency in self.dependencies :
            message += crypto.string_to_byte_array(dependency['contract_id'])
            message += crypto.string_to_byte_array(dependency['state_hash'])

        return message

    # -------------------------------------------------------
    def submit_initialize_transaction(self, ledger_config, **extra_params) :
        """submit the initialize transaction to the ledger
        """

        if self.status is False :
            raise Exception('attempt to submit failed initialization transactions')

        global transaction_dependencies

        # an initialize operation has no previous state
        assert not self.old_state_hash

        initialize_submitter = Submitter(
            ledger_config['LedgerURL'],
            key_str = self.channel_keys.txn_private)

        b64_message_hash = crypto.byte_array_to_base64(self.message_hash)
        b64_new_state_hash = crypto.byte_array_to_base64(self.new_state_hash)
        b64_code_hash = crypto.byte_array_to_base64(self.code_hash)

        txnid = initialize_submitter.submit_ccl_initialize_from_data(
            self.originator_keys.signing_key,
            self.originator_keys.verifying_key,
            self.channel_keys.txn_public,
            self.enclave_service.enclave_id,
            self.signature,
            self.contract_id,
            b64_message_hash,
            b64_new_state_hash,
            self.encrypted_state,
            b64_code_hash,
            **extra_params)

        if txnid :
            transaction_dependencies.SaveDependency(self.contract_id, b64_new_state_hash, txnid)

        return txnid

    # -------------------------------------------------------
    def submit_update_transaction(self, ledger_config, **extra_params):
        """submit the update transaction to the ledger
        """

        if self.status is False :
            raise Exception('attempt to submit failed update transaction')

        global transaction_dependencies

        # there must be a previous state hash if this is
        # an update
        assert self.old_state_hash

        update_submitter = Submitter(
            ledger_config['LedgerURL'],
            key_str = self.channel_keys.txn_private)

        b64_message_hash = crypto.byte_array_to_base64(self.message_hash)
        b64_new_state_hash = crypto.byte_array_to_base64(self.new_state_hash)
        b64_old_state_hash = crypto.byte_array_to_base64(self.old_state_hash)

        # convert contract dependencies into transaction dependencies
        # to ensure that the sawtooth validator does not attempt to
        # re-order the transactions since it is unaware of the semantics
        # of the contract dependencies
        txn_dependencies = set()
        if extra_params.get('transaction_dependency_list') :
            txn_dependencies.update(extra_params['transaction_dependency_list'])

        txnid = transaction_dependencies.FindDependency(ledger_config, self.contract_id, b64_old_state_hash)
        if txnid :
            txn_dependencies.add(txnid)

        for dependency in self.dependencies :
            contract_id = dependency['contract_id']
            state_hash = dependency['state_hash']
            txnid = transaction_dependencies.FindDependency(ledger_config, contract_id, state_hash)
            if txnid :
                txn_dependencies.add(txnid)
            else :
                raise Exception('failed to find dependency; {0}:{1}'.format(contract_id, state_hash))

        if txn_dependencies :
            extra_params['transaction_dependency_list'] = list(txn_dependencies)

        # now send off the transaction to the ledger
        txnid = update_submitter.submit_ccl_update_from_data(
            self.originator_keys.verifying_key,
            self.channel_keys.txn_public,
            self.enclave_service.enclave_id,
            self.signature,
            self.contract_id,
            b64_message_hash,
            b64_new_state_hash,
            b64_old_state_hash,
            self.encrypted_state,
            self.dependencies,
            **extra_params)

        if txnid :
            transaction_dependencies.SaveDependency(self.contract_id, b64_new_state_hash, txnid)

        return txnid
