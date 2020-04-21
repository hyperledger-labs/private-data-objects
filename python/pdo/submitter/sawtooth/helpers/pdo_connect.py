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
import time
import requests
import yaml
import base64
import json
import binascii
import warnings
import secp256k1

from google.protobuf import json_format
from google.protobuf.json_format import MessageToDict

from pdo.submitter.sawtooth.sawtooth_protos.transaction_pb2 import TransactionHeader
from pdo.submitter.sawtooth.sawtooth_protos.transaction_pb2 import Transaction
from pdo.submitter.sawtooth.sawtooth_protos.batch_pb2 import BatchList
from pdo.submitter.sawtooth.sawtooth_protos.batch_pb2 import BatchHeader
from pdo.submitter.sawtooth.sawtooth_protos.batch_pb2 import Batch

from pdo.submitter.sawtooth.pdo_protos.pdo_contract_enclave_registry_pb2 import\
    PdoContractEnclaveInfo,\
    PdoContractEnclaveTransaction,\
    PdoContractEnclaveRegister,\
    PdoContractEnclaveUpdate

from  pdo.submitter.sawtooth.pdo_protos.pdo_contract_registry_pb2 import\
    PdoContractInfo,\
    PdoContractTransaction,\
    PdoContractRegister,\
    PdoContractAddEnclaves,\
    PdoContractRemoveEnclaves

from  pdo.submitter.sawtooth.pdo_protos.pdo_contract_ccl_pb2 import\
    CCL_ContractState,\
    CCL_ContractInformation,\
    CCL_TransactionPayload

from pdo.submitter.sawtooth.helpers.pdo_debug import PdoDbgDump
from pdo.submitter.sawtooth.helpers.pdo_address_helper import PdoAddressHelper

LOGGER = logging.getLogger(__name__)
STATE_TIMEOUT_SEC = 10
__CONTEXTBASE__ = secp256k1.Base(ctx=None, flags=secp256k1.ALL_FLAGS)
__CTX__ = __CONTEXTBASE__.ctx
__PK__ = secp256k1.PublicKey(ctx=__CTX__)  # Cache object to use as factory


class SignerSecp256k1Lib:
    def __init__(self, private_key):
        self._private_key = private_key
        self._public_key_bytes = None

    def sign(self, message):
        try:
            signature = self._private_key.ecdsa_sign(message)
            signature = self._private_key.ecdsa_serialize_compact(signature)
            sig_hex = signature.hex()
            return sig_hex
        except Exception as e:
            raise ClientConnectException('Unable to sign message: {}'.format(str(e)))

    def get_private_key_as_hex(self):
        return binascii.hexlify(self.get_private_key_as_bytes()).decode()

    def get_private_key_as_bytes(self):
        return bytes(self._private_key.private_key)

    def get_public_key_as_hex(self):
        pub_key_hex = binascii.hexlify(self.get_public_key_as_bytes()).decode()
        return pub_key_hex

    def get_public_key_as_bytes(self):
        if not self._public_key_bytes:
            public_key = self._private_key.pubkey

            with warnings.catch_warnings():  # squelch secp256k1 warning
                warnings.simplefilter('ignore')
                self._public_key_bytes = public_key.serialize()

        return self._public_key_bytes


def CreatePdoSawtoothSigner(private_key_str, pdo_crypto=False):
    if not pdo_crypto:
        if not private_key_str:
            sk = secp256k1.PrivateKey(ctx=__CTX__)
            return SignerSecp256k1Lib(sk)
        else:
            try:
                sk = binascii.unhexlify(private_key_str)
                return SignerSecp256k1Lib(secp256k1.PrivateKey(sk, ctx = __CTX__))
            except Exception as e:
                raise ClientConnectException('Unable to parse hex private key: {}'.format(e))

    else:
        # TODO: add PDO crypto lib support here
        raise ClientConnectException('PDO Crypto is not supported')


class PdoRegistryHelper(PdoAddressHelper):
    def __init__(self, url):
        super(PdoRegistryHelper, self).__init__()

        assert url.startswith('http://')
        self.url = url.rstrip('/')

    def send_request(self, suffix, data=None, content_type=None, name=None):
        url = "{}/{}".format(self.url, suffix)
        headers = {}

        if content_type is not None:
            headers['Content-Type'] = content_type

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if result.status_code == 404:
                raise ClientConnectException("No such key: {}".format(name))

            elif not result.ok:
                raise ClientConnectException("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise ClientConnectException(
                'Failed to connect to REST API: {}'.format(err))

        except BaseException as err:
            raise ClientConnectException(err)

        return result.text

    def get_state(self, state_address, output_type, name):
        info = output_type()
        result = self.send_request("state/{}".format(state_address), name=name)
        json = yaml.safe_load(result)
        data = json["data"]
        decoded_data = base64.b64decode(data)
        info.ParseFromString(decoded_data)
        return info

    def get_state_dict(self, state_address, output_type, name):
        msg = self.get_state(state_address, output_type, name)
        return MessageToDict(msg, including_default_value_fields=True, preserving_proto_field_name=True)

    def get_enclave_dict(self, enclave_id):
        return self.get_state_dict(self.get_enclave_address(enclave_id), PdoContractEnclaveInfo, enclave_id)

    def get_contract_dict(self, contract_id):
        return self.get_state_dict(self.get_contract_address(contract_id), PdoContractInfo, contract_id)

    def get_ccl_info_dict(self, contract_id):
        return self.get_state_dict(self.get_ccl_info_address(contract_id), CCL_ContractInformation, contract_id)

    def get_ccl_state_dict(self, contract_id, state_hash):
        return self.get_state_dict(self.get_ccl_state_address(
            contract_id, state_hash),
            CCL_ContractState,
            contract_id + ':' + state_hash
        )


class PdoClientConnectHelper(PdoRegistryHelper):
    def __init__(self, url, keyfile=None, key_str=None, auto_generate=False, cli=False):
        super(PdoClientConnectHelper, self).__init__(url)

        if not cli:
            self._dbg_dump = PdoDbgDump(LOGGER)
        else:
            self._dbg_dump = PdoDbgDump()

        self._make_signer(keyfile, key_str, auto_generate)

    def generate_new_signer_key(self):
        self._make_signer(auto_generate=True)

    def get_signer_public_key_as_hex(self):
         return self._signer.get_public_key_as_hex()

    def get_signer_private_key_as_hex(self):
        return self._signer.get_private_key_as_hex()

    def _make_signer(self, keyfile=None, key_str=None, auto_generate=False):
        if key_str or auto_generate:
            self._signer = CreatePdoSawtoothSigner(key_str)
        elif keyfile:
            try:
                with open(keyfile) as fd:
                    key_str = fd.read().strip()
                    fd.close()
            except OSError as err:
                raise ClientConnectException(
                    'Failed to read private key: {}'.format(str(err)))
            self._signer = CreatePdoSawtoothSigner(key_str)
        else:
            raise ClientConnectException('No option to create a signing key')

    def get_status(self, batch_id, wait):
        try:
            result = self.send_request(
                'batch_statuses?id={}&wait={}'.format(batch_id, wait),)
            return yaml.safe_load(result)['data'][0]['status']
        except BaseException as err:
            raise ClientConnectException(err)

    def send_transaction(self,
                         payload,
                         family,
                         wait=None,
                         transaction_output_list=None,
                         transaction_input_list=None,
                         verbose=False,
                         exception_type=TimeoutError,
                         transaction_dependency_list=None):

        if not transaction_output_list:
            if family == self.get_ccl_family_name():
                transaction_output_list = [self.get_ccl_info_prefix(),
                               self.get_ccl_state_prefix()]
            elif family == self.get_contract_registry_family_name():
                transaction_output_list = [self.get_contract_prefix()]
            else:
                transaction_output_list = [self.get_enclave_prefix()]

        if not transaction_input_list:
            transaction_input_list = [self.get_enclave_prefix(),
                          self.get_contract_prefix(),
                          '000000',
                          self.get_ccl_info_prefix(),
                          self.get_ccl_state_prefix()]

        if verbose:
            self._dbg_dump.dump_str("output_list: {}".format(transaction_output_list))
            self._dbg_dump.dump_str("intput_list: {}".format(transaction_input_list))
            self._dbg_dump.dump_str("family: {}".format(family))
            self._dbg_dump.dump_str("dependency_list: {}".format(transaction_dependency_list))

        header = TransactionHeader(
            signer_public_key=self.get_signer_public_key_as_hex(),
            family_name=family,
            family_version="1.0",
            inputs=transaction_input_list,
            outputs=transaction_output_list,
            dependencies=transaction_dependency_list,
            payload_sha512=self._sha512(payload),
            batcher_public_key=self.get_signer_public_key_as_hex(),
            nonce=time.time().hex().encode()
        ).SerializeToString()

        signature = self._signer.sign(header)

        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=signature
        )
        batch_list = self._create_batch_list([transaction])
        batch_id = batch_list.batches[0].header_signature

        if wait and wait > 0:
            wait_time = 0
            start_time = time.time()
            response = self.send_request(
                "batches", batch_list.SerializeToString(),
                'application/octet-stream',
            )
            while wait_time < wait:
                status = self.get_status(
                    batch_id,
                    wait - int(wait_time),
                )
                wait_time = time.time() - start_time

                if status != 'PENDING':
                    if verbose:
                        self._dbg_dump.dump_str("Transaction status: '{}'".format(status))
                    if status != "COMMITTED" and exception_type:
                        # this is a temporary fix for the fact that Sawtooth  may return INVALID status for a short while after submitting batch for commit
                        # FIX: if total wait time < 10 (ad hoc), and we get INVALID, we wait for 0.1s before checking the status again
                        if wait_time < 10 and wait_time < wait:
                            LOGGER.info("Unexpected status {}. Waiting for 0.1s before rechecking status".format(status))
                            time.sleep(0.1)
                            continue
                        else:
                            raise exception_type("Transaction submission failed with status '{}'".format(status))

                    return response, signature

            if not exception_type:
                return response, signature
            else:
                if verbose:
                    self._dbg_dump.dump_str("Transaction submission timeout")
                raise exception_type("Transaction submission timeout")

        response = self.send_request(
            "batches", batch_list.SerializeToString(),
            'application/octet-stream',
        )

        return response, signature

    def _create_batch_list(self, transactions):
        transaction_signatures = [t.header_signature for t in transactions]

        header = BatchHeader(
            signer_public_key= self.get_signer_public_key_as_hex(),
            transaction_ids=transaction_signatures
        ).SerializeToString()

        signature = self._signer.sign(header)

        batch = Batch(
            header=header,
            transactions=transactions,
            header_signature=signature)

        return BatchList(batches=[batch])

    def execute_json_transaction(self,
                                 json_input,
                                 address_family,
                                 wait,
                                 exception_type=None,
                                 verbose=False,
                                 timeout_exception_type=TimeoutError,
                                 transaction_output_list=None,
                                 transaction_input_list=None,
                                 transaction_dependency_list=None):
        json_dict = json.loads(json_input)
        verb = json_dict['verb']

        if not verb:
            if not exception_type:
                return False
            raise exception_type("no 'verb' in the json input")

        if address_family == self.get_enclave_registry_family_name():
            txn = PdoContractEnclaveTransaction()
            txn.verb = verb
            txn.verifying_key = json_dict.get("verifying_key")
            if verb == 'register':
                details = PdoContractEnclaveRegister()
                proof_data = json_dict.get("proof_data")
                if proof_data is None or isinstance(proof_data, str):
                     json_format.Parse(json_input, details, ignore_unknown_fields=True)
                else:
                    if not exception_type:
                        return False
                    raise exception_type("missing or invalid 'proof_data'")
            elif verb == 'update':
                details = PdoContractEnclaveUpdate()
                json_format.Parse(json_input, details, ignore_unknown_fields=True)
            elif verb == 'delete':
                details = None
            else:
                if not exception_type:
                   return False
                raise exception_type("unknown verb in the json input '{}'".format(verb))

            if details:
                txn.transaction_details = txn.transaction_details = details.SerializeToString()
            if verbose:
                self._dbg_dump.dump_contract_enclave_transaction(txn)
                self._dbg_dump.dump_enclave_transaction_protobuf_message_to_json(txn)

        elif address_family == self.get_contract_registry_family_name():
            txn = PdoContractTransaction()
            txn.verb = verb
            if 'contract_id' in json_dict:
                txn.contract_id = json_dict.get("contract_id")
            if verb == 'register':
                details = PdoContractRegister()
            elif verb == 'add-enclaves':
                details = PdoContractAddEnclaves()
            elif verb == 'remove-enclaves':
                details = PdoContractRemoveEnclaves()
            elif verb == 'delete':
                details = None
            else:
                if not exception_type:
                   return False
                raise exception_type("unknown verb in the json input '{}'".format(verb))

            if details:
                json_format.Parse(json_input, details, ignore_unknown_fields=True)
                txn.transaction_details = details.SerializeToString()

            if verbose:
                self._dbg_dump.dump_contract_transaction(txn)
                self._dbg_dump.dump_contract_transaction_protobuf_message_to_json(txn)

        elif address_family == self.get_ccl_family_name():
            if verb not in ['initialize', 'update', 'terminate', 'delete']:
                if not exception_type:
                    return False
                raise exception_type("unknown verb in the json input '{}'".format(verb))
            txn = CCL_TransactionPayload()
            json_format.Parse(json_input, txn, ignore_unknown_fields=True)
            if verbose:
                self._dbg_dump.dump_ccl_transaction(txn)
                self._dbg_dump.dump_ccl_transaction_protobuf_message_to_json(txn)

        else:
            if not exception_type:
                return False
            raise exception_type(
                "unknown 'af' (a.k.a. address family) in the json input '{}'".format(
                address_family))

        result, signature = self.send_transaction(
            txn.SerializeToString(),
            address_family,
            wait=wait,
            exception_type=timeout_exception_type,
            transaction_output_list=transaction_output_list,
            transaction_input_list=transaction_input_list,
            transaction_dependency_list=transaction_dependency_list
        )

        if verbose:
            self._dbg_dump.dump_str("")
            self._dbg_dump.dump_str(result)
            self._dbg_dump.dump_str("")
            self._dbg_dump.dump_str("Transaction signature: {}".format(signature))

        return signature


class ClientConnectException(Exception):
    pass
