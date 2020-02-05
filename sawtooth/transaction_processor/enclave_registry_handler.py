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
import hashlib
import base64
import json

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.messaging.future import FutureTimeoutError
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.protobuf.setting_pb2 import Setting

from pdo.submitter.sawtooth.pdo_protos.pdo_contract_enclave_registry_pb2 import PdoContractEnclaveInfo
from pdo.submitter.sawtooth.pdo_protos.pdo_contract_enclave_registry_pb2 import PdoContractEnclaveTransaction
from pdo.submitter.sawtooth.pdo_protos.pdo_contract_enclave_registry_pb2 import PdoContractEnclaveRegister
from pdo.submitter.sawtooth.pdo_protos.pdo_contract_enclave_registry_pb2 import PdoContractEnclaveUpdate

from pdo.submitter.sawtooth.helpers.pdo_debug import PdoDbgDump


from common.pdo_signing import verify_enclave_registration_info
from common.pdo_connect_tp import PdoTpConnectHelper


LOGGER = logging.getLogger(__name__)

STATE_TIMEOUT_SEC = 10


class ContractEnclaveRegistryTransactionHandler(TransactionHandler):
    def __init__(self, debug_on, dbg_dump_to_logger=True):
        self.connect = PdoTpConnectHelper()
        self._debug_on = debug_on
        if dbg_dump_to_logger:
            self.dbg_dump = PdoDbgDump(LOGGER)
        else:
            self.dbg_dump = PdoDbgDump()
        LOGGER.debug("Enclave namespace prefix: %s",
                     self.connect.get_enclave_prefix())

    @property
    def family_name(self):
        family = self.connect.get_enclave_registry_family_name()
        LOGGER.debug("Enclave family name: %s", family)
        return family

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return self.connect.get_enclave_prefix()

    def _get_enclave_state(self, context, enclave_id):
        address = self.connect.get_enclave_address(enclave_id)
        return self.connect.get_state(context, address, PdoContractEnclaveInfo)

    def _delete_enclave_state(self, context, enclave_id):
        address = self.connect.get_enclave_address(enclave_id)
        return self.connect.delete_state(context, address)

    def _set_enclave_state(self, context, enclave_id, data):
        address = self.connect.get_enclave_address(enclave_id)
        return self.connect.set_state(context, address, data)

    def _verify_registration_info(self,
                                  payload,
                                  details,
                                  public_key_hash,
                                  context):
        # TODO: Allowing no proof data should be removed in the production version
        if not details.proof_data:
            LOGGER.debug("*** Enclave proof data is empty - simulation mode")
            if not self._debug_on:
                raise InvalidTransaction(
                    'Simulation mode is not allowed when the debug support is OFF')
            return

        # Try to get the report key from the configuration setting.
        # If it is not there, fail verification.
        try:
            report_public_key_pem = self.connect.get_report_public_key(context)
        except KeyError:
            raise \
                ValueError(
                    'Failed to get report public key configuration setting {}'.format(
                        self.connect.get_report_public_key_setting_name()))

        # Retrieve the valid enclave measurement values, converting the comma-
        # delimited list. If it is not there, fail verification.
        try:
            valid_measurements = self.connect.get_valid_measurements(context)
        except KeyError:
            raise \
                ValueError(
                    'Failed to get enclave measurements setting {}'.format(
                        self.connect.get_valid_measurements_setting_name()))

        # Retrieve the valid enclave basename value. If it is not there,
        # fail verification.
        try:
            valid_basenames = self.connect.get_valid_basenames(context)
        except KeyError:
            raise \
                ValueError(
                    'Failed to get enclave basenames setting {}'.format(
                        self.connect.get_valid_basenames_setting_name()))

        verify_enclave_registration_info(self.connect,
                                         payload,
                                         details,
                                         public_key_hash,
                                         context,
                                         report_public_key_pem,
                                         valid_measurements,
                                         valid_basenames)

    # def check_address(context, address, key, register_new):
    def check_address(self, context, key, register_new):
        try:
            state = self._get_enclave_state(context, key)
            if register_new:
                if state.verifying_key:
                    raise InvalidTransaction(
                        'Contract enclave already exist with signing_key {}'\
                        .format(key))
                else:
                    return state
            else:
                if not state.verifying_key:
                    raise InvalidTransaction(
                        'Enclave does not exist: {0}'.format(key))
                else:
                    return state
        except InternalError:
            if not register_new:
                raise InvalidTransaction(
                    'Enclave does not exist: {0}'.format(key))
            else:
                return PdoContractEnclaveInfo()

    def apply(self, transaction, context):
        txn_header = transaction.header
        txn_signer_public_key = txn_header.signer_public_key

        payload = PdoContractEnclaveTransaction()
        payload.ParseFromString(transaction.payload)

        self.dbg_dump.dump_contract_enclave_transaction(payload)
        info = self.check_address(context,
                                  payload.verifying_key,
                                  payload.verb == 'register')

        if payload.verb == 'register':
            public_key_hash = hashlib.sha256(txn_signer_public_key.encode()).hexdigest()
            details = PdoContractEnclaveRegister()
            details.ParseFromString(payload.transaction_details)

            try:
                self._verify_registration_info(payload,
                                               details,
                                               public_key_hash,
                                               context)
            except ValueError as error:
                 raise InvalidTransaction\
                     ('Invalid Signup Info: {}'.format(error))

            info.verifying_key = payload.verifying_key
            info.encryption_key = details.encryption_key
            info.last_registration_block_context = \
                details.registration_block_context
            info.owner_id = txn_signer_public_key
            info.registration_transaction_id = transaction.signature
            info.proof_data = details.proof_data

            self.dbg_dump.dump_contract_enclave_state(info, "Setting new PdoContractEnclaveInfo")
            self._set_enclave_state(context,
                                    payload.verifying_key,
                                    info.SerializeToString())

        elif payload.verb == 'delete' or payload.verb == 'update':
            self.dbg_dump.dump_contract_enclave_state(info, "Received PdoContractEnclaveInfo")

            if payload.verb == 'delete':
                if not self._debug_on:
                    raise InvalidTransaction('Delete is not allowed, debug support is OFF')
                LOGGER.info("Deleting PdoContractEnclaveInfo %s", payload.verifying_key)
                self._delete_enclave_state(context, payload.verifying_key)

            else:
                # Check the contract enclave owner matches transaction signer.
                if info.owner_id != txn_signer_public_key:
                    raise InvalidTransaction(
                        'Owner signature mismatch signer {}, owner {}'
                            .format(info.verifying_key, txn_signer_public_key))

                details = PdoContractEnclaveUpdate()
                details.ParseFromString(payload.transaction_details)
                info.last_registration_block_context = \
                    details.registration_block_context

                self.dbg_dump.dump_contract_enclave_state(info, "Updating existing PdoContractEnclaveInfo")
                self._set_enclave_state(context,
                                        payload.verifying_key,
                                        info.SerializeToString())

        else:
            raise InvalidTransaction('Invalid transaction action {}'
                                     .format(payload.verb))
