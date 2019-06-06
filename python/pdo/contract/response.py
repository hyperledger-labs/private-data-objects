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
import sys
import concurrent.futures
import queue
import time
import threading

import pdo.common.crypto as crypto
import pdo.common.keys as keys

from pdo.contract.state import ContractState
from pdo.contract.replication import ReplicationRequest, start_replication_service, stop_replication_service, add_replication_task
from pdo.contract.transaction import TransactionRequest, start_transaction_processing_service, stop_transacion_processing_service, add_transaction_task

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ContractResponse(object) :
    """
    Class for managing the contract operation response from an enclave service
    """

    __start_commit_service__ = True

    # -------------------------------------------------------
    @staticmethod
    def exit_commit_workers():
        """Set the global variable stop_commit_service to True. This will be picked by the workers"""

        stop_replication_service()
        stop_transacion_processing_service()

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
        self.new_state_object = request.contract_state
        #if the new state is same as the old state, then change set is empty
        self.new_state_object.changed_block_ids=[]
        self.request_number = request.request_number
        self.operation = request.operation

        if self.status and self.state_changed :
            self.signature = response['Signature']
            state_hash_b64 = response['StateHash']

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
            self.new_state_hash = crypto.base64_to_byte_array(state_hash_b64)

            self.originator_keys = request.originator_keys
            self.enclave_service = request.enclave_service

            self.old_state_hash = ()
            if request.operation != 'initialize' :
                self.old_state_hash = ContractState.compute_hash(request.contract_state.raw_state)

            if not self.__verify_enclave_signature(request.enclave_keys) :
                raise Exception('failed to verify enclave signature')

            self.raw_state = self.enclave_service.get_block(state_hash_b64)
            self.new_state_object = ContractState(self.contract_id, self.raw_state)
            self.new_state_object.pull_state_from_eservice(self.enclave_service)

            # compute ids of blocks in the change set (used for replication)
            self.new_state_object.compute_ids_of_newblocks(request.contract_state.component_block_ids)
            self.replication_params = request.replication_params

    # -------------------------------------------------------
    @property
    def commit_id(self):
        if self.status and self.state_changed:
            return (self.contract_id, self.new_state_hash, self.request_number)
        else:
            return None

    # -------------------------------------------------------
    def commit_asynchronously(self, ledger_config=None, wait_parameter_for_ledger=30):
        """Commit includes two steps: First, replicate the change set to all provisioned encalves. Second,
        commit the transaction to the ledger. In this method, we add a job to the replication queue to enable the first step. The job will
        be picked by a replication worker thead. A call_back_after_replication function (see below) is automatically invoked to add a task for the second step """

        #start threads for commiting response if not done before
        if ContractResponse.__start_commit_service__:
            # start replication service
            start_replication_service()
            start_transaction_processing_service()
            ContractResponse.__start_commit_service__ = False

        #create the replication request
        self.replication_request = ReplicationRequest(self.replication_params, self.contract_id, \
            self.new_state_object.changed_block_ids, self.commit_id)

        #create the transaction request if ledger is enabled
        if ledger_config:
            self.transaction_request = TransactionRequest(ledger_config, self.commit_id, wait_parameter_for_ledger)
        else:
            self.transaction_request = None

        #submit the replication task
        add_replication_task(self)

    # -------------------------------------------------------
    def call_back_after_replication(self):
        """this is the call back function after replication. Currently, the call-back's role is to add a new task to the pending transactions queue,
        which will be processed by a "submit transaction" thread whose job is to submit transactions corresponding to completed replication tasks
        """
        if self.transaction_request:
            add_transaction_task(self)

    # -------------------------------------------------------
    def wait_for_commit(self):
        """ Wait for completion of the commit task corresponding to the response. Return transaction id if ledger is used, else return None"""

        # wait for the completion of the replication task
        try:
            self.replication_request.wait_for_completion()
        except Exception as e:
            raise Exception(str(e))

        # wait for the completion of the transaction processing if ledger is in use
        if self.transaction_request:
            try:
                txn_id = self.transaction_request.wait_for_completion()
            except Exception as e:
                raise Exception(str(e))
        else:
            txn_id = None

        return txn_id

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
