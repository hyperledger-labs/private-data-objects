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
import binascii

from sawtooth_sdk.processor.handler import TransactionHandler
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.exceptions import InternalError

from pdo.submitter.sawtooth.pdo_protos.pdo_contract_registry_pb2 import PdoContractInfo
from pdo.submitter.sawtooth.pdo_protos.pdo_contract_registry_pb2 import PdoContractTransaction
from pdo.submitter.sawtooth.pdo_protos.pdo_contract_registry_pb2 import PdoContractRegister
from pdo.submitter.sawtooth.pdo_protos.pdo_contract_registry_pb2 import PdoContractAddEnclaves
from pdo.submitter.sawtooth.pdo_protos.pdo_contract_registry_pb2 import PdoContractRemoveEnclaves
from pdo.submitter.sawtooth.pdo_protos.pdo_contract_enclave_registry_pb2 import PdoContractEnclaveInfo

from pdo.submitter.sawtooth.helpers.pdo_debug import PdoDbgDump

from common.pdo_signing import verify_add_enclave_to_contract_pdo_signature
from common.pdo_signing import verify_add_enclave_to_contract_signature
from common.pdo_signing import verify_contract_register_signature
from common.pdo_connect_tp import PdoTpConnectHelper


LOGGER = logging.getLogger(__name__)
STATE_TIMEOUT_SEC = 10


class ContractRegistryTransactionHandler(TransactionHandler):
    def __init__(self, debug_on, dbg_dump_to_logger=True):
        self.connect = PdoTpConnectHelper()
        self._debug_on = debug_on
        if dbg_dump_to_logger:
            self.dbg_dump = PdoDbgDump(LOGGER)
        else:
            self.dbg_dump = PdoDbgDump()
        LOGGER.debug("Contract namespace prefix: %s",
                     self.connect.get_contract_prefix())

    @property
    def family_name(self):
        family = self.connect.get_contract_registry_family_name()
        LOGGER.debug("Contract family name: %s", family)
        return family

    @property
    def family_versions(self):
        return ['1.0']

    @property
    def namespaces(self):
        return self.connect.get_contract_prefix()

    def _get_enclave_state(self, context, enclave_id):
        address = self.connect.get_enclave_address(enclave_id)
        return self.connect.get_state(context, address, PdoContractEnclaveInfo)

    def _set_contract_state(self, context, contract_id, data):
        address = self.connect.get_contract_address(contract_id)
        self.connect.set_state(context, address, data)

    def _delete_contract_state(self, context, contract_id):
        address = self.connect.get_contract_address(contract_id)
        self.connect.delete_state(context, address)

    def _get_contract_state(self, context, contract_id):
        address = self.connect.get_contract_address(contract_id)
        return self.connect.get_state(context, address, PdoContractInfo)

    def check_address(self, context, contract_id, register_new):
        LOGGER.debug("check_address.address of: %s", contract_id)

        try:
            state = self._get_contract_state(context, contract_id)

            if register_new:
                if state.contract_id:
                    raise InvalidTransaction(
                        'Contract already exists with signing_key {}'\
                        .format(contract_id))
                else:
                    return state
            else:
                if not state.contract_id:
                    raise InvalidTransaction(
                        'Contract does not exist: {0}'.format(contract_id))
                else:
                    return state
        except InternalError as error:
            if not register_new:
                raise InvalidTransaction(
                    'Contract does not exist: {0}'.format(contract_id))
            else:
                return PdoContractInfo()

    @staticmethod
    def _verify_register(reg_info, txn_signer_public_key):
        if not reg_info.contract_code_hash:
            raise InvalidTransaction('Contract code hash is empty')

        if len(reg_info.provisioning_service_ids) == 0:
            raise InvalidTransaction('No provisioning service specified')

        for provisioning_service_id in reg_info.provisioning_service_ids:
            if not provisioning_service_id:
                raise InvalidTransaction('Empty provisioning service id')

        if not verify_contract_register_signature(reg_info, txn_signer_public_key):
            raise InvalidTransaction(
                'Contract register signature is invalid')

    def _verify_enclave_info(self, context, contract_info, enclave_info):
        # enclave_info.contract_enclave_id is not empty
        if not enclave_info.contract_enclave_id:
            raise InvalidTransaction('Empty contract_enclave_id')

        contract_enclave_info = \
            self._get_enclave_state(context, enclave_info.contract_enclave_id)

        # enclave_info.contract_enclave_id is already in the state list
        for c in contract_info.enclaves_info:
            if enclave_info.contract_enclave_id == c.contract_enclave_id:
                raise InvalidTransaction(
                    'Contract enclave id is already in the state list')

        # enclave_info.encrypted_contract_state_encryption_key not empty
        if not enclave_info.encrypted_contract_state_encryption_key:
            raise InvalidTransaction(
                'Empty encrypted_contract_state_encryption_key')

        # enclave_info.enclave_signature is not empty
        if not enclave_info.enclave_signature:
            raise InvalidTransaction('Empty enclave_signature')

        # enclave_info.enclaves_map is not empty
        if len(enclave_info.enclaves_map) == 0:
            raise InvalidTransaction('Empty enclaves_map')

        for m in enclave_info.enclaves_map:
            #  m.provisioning_service_public_key is not empty
            if not m.provisioning_service_public_key:
                raise InvalidTransaction(
                    'Empty provisioning_service_public_key')
            # m.provisioning_service_public_key exists in contract_info
            if not m.provisioning_service_public_key\
                   in contract_info.provisioning_service_ids:
                raise InvalidTransaction(
                    'Provisioning service id {} not in contract'.format(
                        m.provisioning_service_public_key
                    ))
            # m.provisioning_contract_state_secret
            if not m.provisioning_contract_state_secret:
                raise InvalidTransaction(
                    'Empty provisioning_contract_state_secret')

        if not contract_enclave_info.verifying_key:
            raise InvalidTransaction(
                'Unregisteted enclave with id {}'.format(
                enclave_info.contract_enclave_id))

        # verify signature
        if not verify_add_enclave_to_contract_signature(enclave_info, contract_info):
            raise InvalidTransaction('Enclave signature is invalid')

    def apply(self, transaction, context):
        txn_header = transaction.header
        txn_signer_public_key = txn_header.signer_public_key

        payload = PdoContractTransaction()
        payload.ParseFromString(transaction.payload)
        if payload.verb == 'register':
            sig_unxelified = binascii.unhexlify(transaction.signature)
            digest = hashlib.sha256(sig_unxelified).digest()
            sig_base64 = base64.b64encode(digest)
            contract_id = sig_base64.decode("utf-8", "ignore")
        else:
            contract_id = payload.contract_id

        self.dbg_dump.dump_contract_transaction(payload)

        info = self.check_address(context,
                                  contract_id,
                                  payload.verb == 'register')

        if payload.verb != 'register':
            self.dbg_dump.dump_contract_state(info, "Received PdoContractInfo")

        if payload.verb == 'register':
            details = PdoContractRegister()
            details.ParseFromString(payload.transaction_details)

            self._verify_register(details, txn_signer_public_key)

            info.contract_id = contract_id
            info.contract_code_hash = details.contract_code_hash
            info.pdo_contract_creator_pem_key = details.pdo_contract_creator_pem_key
            for id in details.provisioning_service_ids:
                info.provisioning_service_ids.append(id)

            self.dbg_dump.dump_contract_state(info, "Setting new PdoContractInfo")
            self._set_contract_state(context, contract_id, info.SerializeToString())
            LOGGER.info("Contract %s was added to the registry.", payload.contract_id)

        elif payload.verb == 'delete':
            if not self._debug_on:
                raise InvalidTransaction('Delete is not allowed, debug support is OFF')

            LOGGER.info("Contract %s was deleted", payload.contract_id)
            self._delete_contract_state(context, contract_id)

        elif payload.verb == 'add-enclaves':
            details = PdoContractAddEnclaves()
            details.ParseFromString(payload.transaction_details)

            if not verify_add_enclave_to_contract_pdo_signature(details, info, txn_signer_public_key):
                raise InvalidTransaction('Overall PDO signature for add enclaves transaction is invalid')

            for enclave_info in details.enclaves_info:
                self._verify_enclave_info(context, info, enclave_info)

            for ei in details.enclaves_info:
                enclave_info = info.enclaves_info.add()
                enclave_info.CopyFrom(ei)

            self.dbg_dump.dump_contract_state(info, "PdoContractInfo After adding enclave(s)")
            self._set_contract_state(context, contract_id, info.SerializeToString())
            LOGGER.info("Enclaves were added to contract %s.", payload.contract_id)

        elif payload.verb == 'remove-enclaves':
            details = PdoContractRemoveEnclaves()
            details.ParseFromString(payload.transaction_details)

            for id in details.contract_enclave_ids:
                for ei in info.enclaves_info:
                    if ei.contract_enclave_id == id:
                        info.enclaves_info.remove(ei)
                        break

            self.dbg_dump.dump_contract_state(info, "PdoContractInfo after removing enclave(s)")
            self._set_contract_state(context, contract_id, info.SerializeToString())
            LOGGER.info("Enclaves were removed from contract %s.", payload.contract_id)

        else:
            raise InvalidTransaction('Invalid transaction action {}'
                                     .format(payload.verb))
