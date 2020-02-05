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

import logging

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction

from pdo.submitter.sawtooth.pdo_protos.pdo_contract_registry_pb2 import PdoContractInfo
from pdo.submitter.sawtooth.pdo_protos.pdo_contract_enclave_registry_pb2 import PdoContractEnclaveInfo
from pdo.submitter.sawtooth.pdo_protos.pdo_contract_ccl_pb2 import CCL_ContractState
from pdo.submitter.sawtooth.pdo_protos.pdo_contract_ccl_pb2 import CCL_ContractInformation
from pdo.submitter.sawtooth.pdo_protos.pdo_contract_ccl_pb2 import CCL_TransactionPayload

from pdo.submitter.sawtooth.helpers.pdo_debug import PdoDbgDump

from common.pdo_signing import verify_ccl_transaction_pdo_signature
from common.pdo_signing import verify_ccl_transaction_signature
from common.pdo_connect_tp import PdoTpConnectHelper


LOGGER = logging.getLogger(__name__)

STATE_TIMEOUT_SEC = 10

class ContractCclTransactionHandler(TransactionHandler):
    def __init__(self, debug_on, dbg_dump_to_logger=True):
        self.connect = PdoTpConnectHelper()
        self._debug_on = debug_on
        if dbg_dump_to_logger:
            self.dbg_dump = PdoDbgDump(LOGGER)
        else:
            self.dbg_dump = PdoDbgDump()
        LOGGER.debug("CCL state namespace prefix: %s",
                     self.connect.get_ccl_state_prefix())
        LOGGER.debug("CCL information namespace prefix: %s",
                     self.connect.get_ccl_info_prefix())
        LOGGER.debug("Contract namespace prefix: %s",
                 self.connect.get_contract_prefix())
        LOGGER.debug("Enclave namespace prefix: %s",
                     self.connect.get_enclave_prefix())

    @property
    def family_name(self):
        family = self.connect.get_ccl_family_name()
        LOGGER.debug("CCL family name: %s", family)
        return family

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return [self.connect.get_ccl_state_prefix(),
                self.connect.get_ccl_info_prefix()]

    def _set_ccl_state(self, context, ccl_state):
        self.connect.set_state(context,
                               self.connect.get_ccl_state_address(
                                   ccl_state.state_update.contract_id,
                                   ccl_state.state_update.current_state_hash),
                               ccl_state.SerializeToString())

    def _get_ccl_state(self, context, contract_id, state_hash):
        address = self.connect.get_ccl_state_address(contract_id, state_hash)
        return self.connect.get_state(context, address, CCL_ContractState)

    def _delete_ccl_state(self, context, contract_id, state_hash):
        address = self.connect.get_ccl_state_address(contract_id, state_hash)
        self.connect.delete_state(context, address)

    def _set_ccl_info(self, context, ccl_info):
        address = self.connect.get_ccl_info_address(ccl_info.contract_id)
        self.connect.set_state(context, address, ccl_info.SerializeToString())

    def _get_ccl_info(self, context, contract_id):
        address = self.connect.get_ccl_info_address(contract_id)
        result = self.connect.get_state(context,
                                        address,
                                        CCL_ContractInformation)
        return result

    def _delete_ccl_info(self, context, contract_id):
        address = self.connect.get_ccl_info_address(contract_id)
        self.connect.delete_state(context, address)

    def _get_contract_info(self, context, contract_id):
        address = self.connect.get_contract_address(contract_id)
        return self.connect.get_state(context, address, PdoContractInfo)

    def _get_enclave_info(self, context, enclave_id):
        address = self.connect.get_enclave_address(enclave_id)
        return self.connect.get_state(context, address, PdoContractEnclaveInfo)

    def _verify_common(self, context, payload, signer, initialize=False):
        # check that signer matches channel_id
        if payload.channel_id != signer:
            raise InvalidTransaction(
                "Payload channel id '{0}' doesn't match signer '{1}'".format(
                    payload.channel_id,
                    signer))

        # check that this contract exists
        contract = self._get_contract_info(context,
                                           payload.state_update.contract_id)
        if payload.state_update.contract_id != contract.contract_id:
            raise InvalidTransaction(
                'No contract in registry {}'.format(
                    payload.state_update.contract_id))

        # check that this enclave exists
        enclave = self._get_enclave_info(context,
                                         payload.contract_enclave_id)
        if payload.contract_enclave_id != enclave.verifying_key:
            raise InvalidTransaction(
                'Enclave does not exist for {}'.format(
                    payload.contract_enclave_id))

        # check that this enclave is added to the contract
        enclave_found = False
        for e in contract.enclaves_info:
            if e.contract_enclave_id == payload.contract_enclave_id:
                enclave_found = True
                break

        if not enclave_found:
            raise InvalidTransaction(
                'Enclave {0} has not been added to contract {1}'.format(
                    payload.contract_enclave_id,
                    payload.state_update.contract_id))

        # check dependencies
        for d in payload.state_update.dependency_list:
            state = self._get_ccl_state(context,
                                        d.contract_id,
                                        d.state_hash)

            if not state.state_update.contract_id:
                raise InvalidTransaction(
                    "Dependency doesn't exist for '{0}' '{1}'".format(
                        d.contract_id,
                        d.state_hash
                    ))

        # check enclave signature
        if not verify_ccl_transaction_signature(payload, contract):
            raise InvalidTransaction('Contract CCL enclave signature is invalid')

        # verify PDO signature
        if initialize:
            if not verify_ccl_transaction_pdo_signature(payload, contract):
                raise InvalidTransaction('Contract CCL Initialize PDO signature is invalid')

    def _check_current_ccl_state_and_info(self, context, payload):
        info = self._get_ccl_info(context,
                                  payload.state_update.contract_id)
        self.dbg_dump.dump_ccl_info(info)

        if payload.verb == 'initialize':
            if info.contract_id:
                raise InvalidTransaction(
                    'CCL Contract already exists for {}'.format(
                        payload.state_update.contract_id))
        else:
            if not info.contract_id:
                raise InvalidTransaction(
                    'CCL Contract does not exist: {0}'.format(
                        payload.state_update.contract_id))
            else:
                if not info.is_active:
                    raise InvalidTransaction(
                        'CCL Contract has been terminated: {0}'.format(
                            payload.state_update.contract_id))

                state = self._get_ccl_state(context,
                                            info.current_state.contract_id,
                                            info.current_state.state_hash)
                self.dbg_dump.dump_ccl_state(state)

                if state.state_update.contract_id !=\
                        info.current_state.contract_id\
                        or\
                        state.state_update.current_state_hash != \
                        info.current_state.state_hash:
                    raise InvalidTransaction(
                        "CCL Contract state doesn't exist or invalid")

                return state

        # return new state in case of "initialize" action
        return CCL_ContractState()

    def _verify_initialize(self, context, payload, signer):
        if payload.state_update.previous_state_hash:
            raise InvalidTransaction(
                'Previous state hash must be empty on initialize')

        if len(payload.state_update.dependency_list) != 0:
            raise InvalidTransaction(
                'Dependency list must be empty on initialize')

        self._check_current_ccl_state_and_info(context, payload)
        self._verify_common(context, payload, signer, True)

    def _verify_update(self, context, payload, signer):
        state = self._check_current_ccl_state_and_info(context, payload)
        if payload.state_update.previous_state_hash !=\
                state.state_update.current_state_hash:
            raise InvalidTransaction(
                'Previous state hash in transcation {0}'\
                'mismatches current {1}'.format(
                    payload.state_update.previous_state_hash,
                    state.state_update.current_state_hash))

        self._verify_common(context, payload, signer)
        return state

    def _verify_terminate(self, context, payload, signer):
        state = self._check_current_ccl_state_and_info(context, payload)
        if payload.state_update.previous_state_hash !=\
                state.state_update.current_state_hash:
            raise InvalidTransaction(
                'Previous state hash in transcation {0}'\
                'mismatches current {1}'.format(
                    payload.state_update.previous_state_hash,
                    state.state_update.current_state_hash))

        if payload.state_update.current_state_hash:
            raise InvalidTransaction(
                'Current state hash must be empty on terminate')

        self._verify_common(context, payload, signer)
        return state

    def _complete_action(self, context, transaction, payload, contract_id):
        ccl_state = CCL_ContractState()
        ccl_info = CCL_ContractInformation()

        ccl_state.transaction_id = transaction.signature
        ccl_state.state_update.CopyFrom(payload.state_update)

        ccl_info.contract_id = \
            payload.state_update.contract_id
        ccl_info.is_active = \
            True if payload.verb != 'terminate' else False
        ccl_info.current_state.contract_id = \
            ccl_state.state_update.contract_id
        ccl_info.current_state.state_hash = \
            ccl_state.state_update.current_state_hash

        self.dbg_dump.dump_ccl_info(ccl_info)
        self.dbg_dump.dump_ccl_state(ccl_state)

        if payload.verb != 'terminate':
            self._set_ccl_state(context, ccl_state)
        else:
            ccl_info.current_state.state_hash = \
                payload.state_update.previous_state_hash

        self._set_ccl_info(context, ccl_info)

    def apply(self, transaction, context):
        txn_header = transaction.header
        txn_signer_public_key = txn_header.signer_public_key

        payload = CCL_TransactionPayload()
        payload.ParseFromString(transaction.payload)
        self.dbg_dump.dump_ccl_transaction(payload)

        if payload.verb == 'initialize':
            self._verify_initialize(context, payload, txn_signer_public_key)
            self._complete_action(context,
                                  transaction,
                                  payload,
                                  payload.state_update.contract_id)
            LOGGER.info("Contract CCL initialized for contract %s",
                        payload.state_update.contract_id)

        elif payload.verb == 'update':
            contract_id = self._verify_update(context, payload, txn_signer_public_key)
            self._complete_action(context, transaction, payload, contract_id)
            LOGGER.info("Contract CCL updated for contract %s",
                        payload.state_update.contract_id)

        elif payload.verb == 'terminate':
            contract_id = self._verify_terminate(context, payload, txn_signer_public_key)
            self._complete_action(context, transaction, payload, contract_id)
            LOGGER.info("Contract CCL updated for contract %s",
                        payload.state_update.contract_id)

        elif payload.verb == 'delete':
            # 'delete' is useful for development/testing
            # it should be removed from the production
            # it is for debug only so no verification
            # 1) delete states listed in state_update.dependencies_list

            if not self._debug_on:
                raise InvalidTransaction('Delete is not allowed, debug support is OFF')

            for d in payload.state_update.dependency_list:
                state = self._get_ccl_state(context,
                                            d.contract_id,
                                            d.state_hash)
                if state.state_update.contract_id != d.contract_id:
                    LOGGER.info("CCL state doesn't exist for '%s':'%s'",
                                d.contract_id,
                                d.state_hash)

                else:
                    self._delete_ccl_state(context, d.contract_id, d.state_hash)
                    LOGGER.info("CCL state deleted for '%s':'%s'",
                                d.contract_id,
                                d.state_hash)

            # 2) if payload.state_update.contract_id != "" remove info also
            if payload.state_update.contract_id:
                info = self._get_ccl_info(context,
                                          payload.state_update.contract_id)
                if info.current_state.contract_id != \
                        payload.state_update.contract_id:
                    LOGGER.info("CCL info doesn't exist for '%s'",
                                payload.state_update.contract_id)
                else:
                    self._delete_ccl_info(context,
                                           payload.state_update.contract_id)
                    LOGGER.info("CCL info deleted for %s",
                                payload.state_update.contract_id)

        else:
            raise InvalidTransaction('Invalid transaction verb {}'
                                     .format(payload.verb))
