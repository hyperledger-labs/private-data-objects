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

from pdo.contract.invocation import invocation_response
import pdo.common.crypto as crypto
from pdo.common.utility import deprecated

from pdo.contract.exceptions import InvocationException
from pdo.contract.state import ContractState

from pdo.contract.replication import ReplicationRequest
from pdo.contract.replication import start_replication_service
from pdo.contract.replication import stop_replication_service
from pdo.contract.replication import add_replication_task
from pdo.contract.transaction import TransactionRequest
from pdo.contract.transaction import start_transaction_processing_service
from pdo.contract.transaction import stop_transacion_processing_service
from pdo.contract.transaction import add_transaction_task

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

        if ContractResponse.__start_commit_service__ is False: #if True no service has yet been started
            stop_replication_service()
            stop_transacion_processing_service()

    # -------------------------------------------------------
    def __init__(self, request, response) :
        """
        Initialize a contract response object

        :param request: the ContractRequest object corresponding to the response
        :param response: diction containing the response from the enclave
        """

        self.state_changed = False
        self.status = response['Status']
        self.invocation_response_raw = response['InvocationResponse']
        self.invocation_response = invocation_response(response['InvocationResponse'])
        self.new_state_object = request.contract_state
        self.new_state_object.changed_block_ids=[]

        self.channel_keys = request.channel_keys
        self.channel_id = request.channel_id
        self.contract_id = request.contract_id
        self.creator_id = request.creator_id
        self.code_hash = request.contract_code.compute_hash()
        self.message_hash = request.message.compute_hash()

        self.originator_keys = request.originator_keys
        self.enclave_service = request.enclave_service

        self.dependencies = []


    # -------------------------------------------------------
    @property
    @deprecated
    def result(self):
        return self.invocation_response

    # -------------------------------------------------------
    @property
    def commit_id(self):
        return (self.contract_id, self.new_state_hash, self.request_number)

    # -------------------------------------------------------
    def commit_asynchronously(self, ledger_config=None, wait_parameter_for_ledger=30):
        """Commit includes two steps: First, replicate the change set to
        all provisioned encalves. Second, commit the transaction to the
        ledger. In this method, we add a job to the replication queue to
        enable the first step. The job will be picked by a replication
        worker thead. A call_back_after_replication function (see below)
        is automatically invoked to add a task for the second step
        """

        #start threads for commiting response if not done before
        if ContractResponse.__start_commit_service__:
            # start replication service
            start_replication_service()
            start_transaction_processing_service()
            ContractResponse.__start_commit_service__ = False

        #create the replication request
        self.replication_request = ReplicationRequest(
            self.replication_params,
            self.contract_id,
            self.new_state_object.changed_block_ids,
            self.commit_id)

        #create the transaction request if ledger is enabled
        if ledger_config:
            self.transaction_request = TransactionRequest(ledger_config, self.commit_id, wait_parameter_for_ledger)
        else:
            self.transaction_request = None

        #submit the replication task
        add_replication_task(self)

    # -------------------------------------------------------
    def call_back_after_replication(self):
        """this is the call back function after replication. Currently,
        the call-back's role is to add a new task to the pending
        transactions queue, which will be processed by a "submit
        transaction" thread whose job is to submit transactions
        corresponding to completed replication tasks
        """
        if self.transaction_request:
            add_transaction_task(self)

    # -------------------------------------------------------
    def wait_for_commit(self):
        """Wait for completion of the commit task corresponding to the
        response. Return transaction id if ledger is used, else return
        None"""

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
    def verify_enclave_signature(self, message, enclave_keys) :
        """verify the signature of the response
        """
        return enclave_keys.verify(message, self.signature, encoding = 'b64')

    # -------------------------------------------------------
    def serialize_for_signing(self) :
        """serialize the response for enclave signature verification"""

        message = crypto.string_to_byte_array(self.channel_id)
        message += crypto.string_to_byte_array(self.contract_id)

        message += self.code_hash
        message += self.message_hash

        return message

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class InitializeStateResponse(ContractResponse) :
    def __init__(self, request, response, **kwargs) :
        super().__init__(request, response, **kwargs)

        self.state_changed = True
        self.request_number = request.request_number
        self.operation = 'initialize'

        self.metadata_hash = crypto.base64_to_byte_array(response['MetadataHash'])
        self.signature = response['Signature']

        # save the information we will need for the transaction
        state_hash_b64 = response['StateHash']
        self.new_state_hash = crypto.base64_to_byte_array(state_hash_b64)

        message = self.serialize_for_signing()
        if not self.verify_enclave_signature(message, request.enclave_keys) :
            raise InvocationException('failed to verify enclave signature')

        self.raw_state = self.enclave_service.get_block(state_hash_b64)
        self.new_state_object = ContractState(self.contract_id, self.raw_state)
        self.new_state_object.pull_state_from_eservice(self.enclave_service)

        # compute ids of blocks in the change set (used for replication)
        self.new_state_object.compute_new_block_ids(request.contract_state.component_block_ids)
        self.replication_params = request.replication_params

    # -------------------------------------------------------
    def serialize_for_signing(self) :
        """serialize the response for enclave signature verification"""

        message = super().serialize_for_signing()
        message += crypto.string_to_byte_array(self.creator_id)
        message += self.metadata_hash
        message += self.new_state_hash

        return message

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class UpdateStateResponse(ContractResponse) :
    def __init__(self, request, response, **kwargs) :
        super().__init__(request, response, **kwargs)

        self.state_changed = True
        self.request_number = request.request_number
        self.operation = 'update'

        self.signature = response['Signature']

        # we have another mismatch between the field names in the enclave
        # and the field names expected in the transaction; this needs to
        # be fixed at some point
        for dependency in response['Dependencies'] :
            contract_id = dependency['ContractID']
            state_hash = dependency['StateHash']
            self.dependencies.append({'contract_id' : contract_id, 'state_hash' : state_hash})

        # save the information we will need for the transaction
        state_hash_b64 = response['StateHash']
        self.new_state_hash = crypto.base64_to_byte_array(state_hash_b64)
        self.old_state_hash = ContractState.compute_state_hash(request.contract_state.raw_state)

        message = self.serialize_for_signing()
        if not self.verify_enclave_signature(message, request.enclave_keys) :
            raise Exception('failed to verify enclave signature')

        self.raw_state = self.enclave_service.get_block(state_hash_b64)
        self.new_state_object = ContractState(self.contract_id, self.raw_state)
        self.new_state_object.pull_state_from_eservice(self.enclave_service)

        # compute ids of blocks in the change set (used for replication)
        self.new_state_object.compute_new_block_ids(request.contract_state.component_block_ids)
        self.replication_params = request.replication_params

    # -------------------------------------------------------
    def serialize_for_signing(self) :
        """serialize the response for enclave signature verification"""

        message = super().serialize_for_signing()

        message += self.old_state_hash
        message += self.new_state_hash

        for dependency in self.dependencies :
            message += crypto.string_to_byte_array(dependency['contract_id'])
            message += crypto.string_to_byte_array(dependency['state_hash'])

        return message
