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

import base64
import yaml
import json
import time
import datetime

from google.protobuf import json_format

from sawtooth.sawtooth_protos.setting_pb2 import Setting
from sawtooth.sawtooth_protos.settings_pb2 import SettingsPayload
from sawtooth.sawtooth_protos.settings_pb2 import SettingProposal

from sawtooth.pdo_protos.pdo_contract_enclave_registry_pb2 import PdoContractEnclaveInfo
from sawtooth.pdo_protos.pdo_contract_enclave_registry_pb2 import PdoContractEnclaveTransaction

from sawtooth.pdo_protos.pdo_contract_registry_pb2 import PdoContractInfo
from sawtooth.pdo_protos.pdo_contract_registry_pb2 import PdoContractTransaction
from sawtooth.pdo_protos.pdo_contract_registry_pb2 import PdoContractRegister
from sawtooth.pdo_protos.pdo_contract_registry_pb2 import PdoContractAddEnclaves
from sawtooth.pdo_protos.pdo_contract_registry_pb2 import PdoContractRemoveEnclaves

from sawtooth.pdo_protos.pdo_contract_ccl_pb2 import CCL_ContractState
from sawtooth.pdo_protos.pdo_contract_ccl_pb2 import CCL_ContractInformation
from sawtooth.pdo_protos.pdo_contract_ccl_pb2 import CCL_TransactionPayload

from sawtooth.helpers.pdo_debug import PdoDbgDump
from sawtooth.helpers.pdo_connect import PdoClientConnectHelper
from sawtooth.helpers.pdo_connect import ClientConnectException
from sawtooth.helpers.pdo_address_helper import short_hash

from common.pdo_signing import make_ccl_transaction_pdo_hash_input
from common.pdo_signing import make_add_enclave_to_contract_pdo_hash_input
from common.pdo_signing import make_contract_register_hash_input
from common.pdo_signing import generate_private_key_as_hex
from common.pdo_signing import get_public_key_as_hex
from common.pdo_signing import sign_ccl_transaction
from common.pdo_signing import make_add_enclave_to_contract_hash_input
from common.pdo_signing import secp256k1_sign

from common.create_test_enclave import CreateTestEnclavePayload


SETTINGS_NAMESPACE = '000000'
_MAX_KEY_PARTS = 4
_ADDRESS_PART_SIZE = 16

address_skip_list = []


class PdoCliException(Exception):
    pass


class PdoCliClient:
    _ping_transcation_base = '''{
    "af" : "pdo_contract_instance_registry",
    "verb": "register",
    "contract_code_hash": "code-hash-ping",
    "pdo_contract_creator_pem_key": "",
    "pdo_signature": "",
    "provisioning_service_ids": ["__ping__","'''

    def __init__(self, url, verbose, keyfile=None, enclave_signing_private_key= None):
        if keyfile:
            self.connect = PdoClientConnectHelper(url, keyfile)
        else:
            self.connect = PdoClientConnectHelper(url, auto_generate=True)

        self._verbose = verbose
        self._enclave_signing_private_key = enclave_signing_private_key
        if self._verbose:
            print("enclave_signing_private_key:", enclave_signing_private_key)
            print("keyfile:", keyfile)

    def _send_enclave_transaction(self, txn, wait):
        if self._verbose:
            PdoDbgDump().dump_contract_enclave_transaction(txn)
            PdoDbgDump().dump_enclave_transaction_protobuf_message_to_json(txn)

        return self.connect.send_transaction(
            txn.SerializeToString(),
            self.connect.get_enclave_registry_family_name(),
            wait=wait)

    def _send_contract_transaction(self, txn, wait):
        if self._verbose:
            PdoDbgDump().dump_contract_transaction(txn)
            PdoDbgDump().dump_contract_transaction_protobuf_message_to_json(txn)
        return self.connect.send_transaction(
            txn.SerializeToString(),
            self.connect.get_contract_registry_family_name(),
            wait=wait)

    def _send_ccl_transaction(self, txn, wait):
        if self._verbose:
            PdoDbgDump().dump_ccl_transaction(txn)
            PdoDbgDump().dump_ccl_transaction_protobuf_message_to_json(txn)
        return self.connect.send_transaction(
            txn.SerializeToString(),
            self.connect.get_ccl_family_name(),
            wait=wait)

    def _get_enclave_state(self, enclave_id):
        try:
            info = self.connect.get_state(
                self.connect.get_enclave_address(enclave_id),
                PdoContractEnclaveInfo,
                enclave_id)
            return info
        except BaseException as err:
            print(err)
        except ClientConnectException as err:
            print(err)

        return PdoContractEnclaveInfo()

    def _get_contract_state(self, contract_id, silent=False):
        try:
            info = self.connect.get_state(
                self.connect.get_contract_address(contract_id),
                PdoContractInfo,
                contract_id)
            return info
        except BaseException as err:
            if not silent:
                print(err)
        except ClientConnectException as err:
            if not silent:
                print(err)

        return PdoContractInfo()

    def _get_ccl_info_state(self, ccl_info_id):
        try:
            info = self.connect.get_state(
                self.connect.get_ccl_info_address(ccl_info_id),
                CCL_ContractInformation,
                ccl_info_id)
            return info
        except BaseException as err:
            print(err)
        except ClientConnectException as err:
            print(err)

        return CCL_ContractInformation()

    def _get_ccl_state_state(self, contract_id, state_hash):
        try:
            info = self.connect.get_state(
                self.connect.get_ccl_state_address(contract_id, state_hash),
                CCL_ContractState,
                contract_id + ":" + state_hash)
            return info
        except BaseException as err:
            print(err)
        except ClientConnectException as err:
            print(err)

        return CCL_ContractState()

    def _show_config_setting(self, key_name):
        address = self.connect.get_setting_address(key_name)

        if self._verbose:
            print("requesting setting:", key_name)
            print("address:", address)

        try:
            result = self.connect.send_request(
                "state/{}".format(address),
                name=key_name)

            json = yaml.safe_load(result)
            data = json["data"]
            decoded_data = base64.b64decode(data)

            try:
                settings = Setting()
                settings.ParseFromString(decoded_data)
                print("Settings: {}".format(key_name))
                for entry in settings.entries:
                    print("key:", entry.key)
                    print("value:", entry.value)
            except BaseException:
                return "Failed to parse result"

        except ClientConnectException as err:
            print(err)
            return "State not found"

        return "OK"

    def _show_config_setting_list(self, address="000000"):
        try:
            result = self.connect.send_request(
                "state?address={}".format(address),
                name="settings")

            json = yaml.safe_load(result)
            data = json["data"]

            if self._verbose:
                print("json:", json)
                print("")

            for entry in data:
                decoded_data = base64.b64decode(entry["data"])
                settings = Setting()
                settings.ParseFromString(decoded_data)
                for entry in settings.entries:
                    print("key:", entry.key)
                    print("value:", entry.value)
                    print("")

        except ClientConnectException as err:
            print(err)
            return "State not found"
        except BaseException:
            print("Failed to parse result")
            return "Failed to parse result"

        return "OK"

    def get_setting_list(self, wait=None):
        self._show_config_setting_list()
        return "OK"

    def _find_contract_id(self, provisioning_id_filter="p1"):
        contract = None
        prev_address = "'"
        prefix = self.connect.get_contract_prefix()
        next_url = "state?address={0}".format(prefix)
        while next_url:
            result = self.connect.send_request(next_url, name=prefix)
            json = yaml.safe_load(result)

            next_url = ""
            try:
                paging = json["paging"]
                next_url = paging["next"]
                domain_end = next_url.find("/", 7)
                next_url = next_url[(domain_end + 1):]
            except KeyError:
                pass

            data = json["data"]

            for entry in data:
                decoded_data = base64.b64decode(entry["data"])
                address = entry["address"]
                if address not in address_skip_list:
                    current_contract = PdoContractInfo()
                    current_contract.ParseFromString(decoded_data)
                    if provisioning_id_filter in current_contract.provisioning_service_ids:
                        if contract:
                            raise PdoCliException(
                                "Contract id retrievel failed - multiple candidates\n'{0}'\nand\n'{1}'".format(
                                    prev_address,
                                    address))
                        contract = current_contract
                else:
                    if self._verbose:
                        print("skipping contract entry:", address)

        if not contract:
            raise PdoCliException("Contract id retrievel failed - no candidates")

        return contract

    def _to_base64(self, str):
        try:
            base64.b64decode(str, validate=True)
        except:
            return base64.b64encode(bytes(str, "utf-8")).decode("utf-8", "ignore")

        return str  # already base64

    def execute_json_transaction(self, json_input, address_family, wait):
        if self._verbose:
            print("\njson_input:")
            print(json_input)

        json_dict = json.loads(json_input)
        if not address_family:
            try:
                address_family = json_dict['af']
            except:
                raise PdoCliException(
                    "Family not defined, use 'af'in the json or --enclave, --contract, or --ccl on the command line")

        # set contract id and signature(s) if they are empty in case of contract add and remove enclaves transactions
        if address_family == self.connect.get_contract_registry_family_name():
            if json_dict['verb'] != 'delete':
                details = None
                contract = None

                if json_dict['verb'] != 'register' and not json_dict['contract_id']:
                    contract = self._find_contract_id()

                if json_dict['verb'] == 'register':
                    # generate pdo_signature and pdo_contract_creator_pem_key in case of contract register
                    details = PdoContractRegister()
                    json_format.Parse(json_input, details, ignore_unknown_fields=True)

                    details.contract_code_hash = self._to_base64(details.contract_code_hash)

                    # normally it would be done using one time transaction signing key
                    # to simplify test automation we are going to reuse the same key was used for contract registration
                    details.pdo_signature = secp256k1_sign(
                        make_contract_register_hash_input(details, self.connect.get_signer_public_key_as_hex()),
                        self.connect.get_signer_private_key_as_hex()
                    )
                    details.pdo_contract_creator_pem_key = self.connect.get_signer_public_key_as_hex()
                    contract = PdoContractInfo()
                    if 'contract_id' in json_dict:
                        contract.contract_id = json_dict.get('contract_id')
                elif json_dict['verb'] == 'remove-enclaves':
                    details = PdoContractRemoveEnclaves()
                    json_format.Parse(json_input, details, ignore_unknown_fields=True)
                elif json_dict['verb'] == 'add-enclaves':
                    details = PdoContractAddEnclaves()
                    json_format.Parse(json_input, details, ignore_unknown_fields=True)
                    # generate enclave signatures for each enclave info
                    # if signatures are empty in the json input
                    for enclave_info in details.enclaves_info:
                        if not enclave_info.enclave_signature:
                            if not contract:
                                contract = self._get_contract_state(json_dict['contract_id'])
                                if not not contract or not contract.contract_id:
                                    raise PdoCliException(
                                        "Cannot load contract to generate signature {}".format(json_dict['contract_id']))

                        enclave_info.encrypted_contract_state_encryption_key = \
                            base64.b64encode(enclave_info.encrypted_contract_state_encryption_key.encode())

                        hash_input = make_add_enclave_to_contract_hash_input(enclave_info, contract)
                        enclave_info.enclave_signature = secp256k1_sign(hash_input, self._enclave_signing_private_key)

                    contract_creator_private_key = self.connect.get_signer_private_key_as_hex()
                    self.connect.generate_new_signer_key()
                    details.pdo_signature = secp256k1_sign(
                        make_add_enclave_to_contract_pdo_hash_input(
                            details,
                            contract,
                            self.connect.get_signer_public_key_as_hex()),
                        contract_creator_private_key
                    )

                if contract:
                    txn = PdoContractTransaction()
                    txn.verb = json_dict['verb']
                    txn.contract_id = contract.contract_id
                    if details:
                        txn.transaction_details = details.SerializeToString()
                    if self._verbose:
                        print("Updated Contract Transaction:")
                        PdoDbgDump().dump_contract_transaction(txn)
                        PdoDbgDump().dump_contract_transaction_protobuf_message_to_json(txn)

                    result = self.connect.send_transaction(txn.SerializeToString(), address_family, wait=wait)
                    if self._verbose:
                        print(result)

                    print("OK")
                    return

        # set contract id and signature(s) if they are empty in case of CCL transactions
        if address_family == self.connect.get_ccl_family_name():
            if json_dict['verb'] != 'delete':
                signature = json_dict['contract_enclave_signature']
                contract_id = json_dict['state_update']['contract_id']

                if not contract_id or not signature:
                    contract_creator_private_key = self.connect.get_signer_private_key_as_hex()
                    self.connect.generate_new_signer_key()

                    txn = CCL_TransactionPayload()
                    json_format.Parse(json_input, txn, ignore_unknown_fields=True)

                    # for testing set channel_id to the one time transaction signer key
                    txn.channel_id = self.connect.get_signer_public_key_as_hex()

                    if not contract_id:
                        contract = self._find_contract_id()
                    else:
                        contract = self._get_contract_state(contract_id)

                    txn.state_update.contract_id = contract.contract_id
                    for d in txn.state_update.dependency_list:
                        d.contract_id = contract.contract_id
                        d.state_hash = self._to_base64(d.state_hash)

                    txn.state_update.current_state_hash = self._to_base64(txn.state_update.current_state_hash)
                    txn.state_update.previous_state_hash = self._to_base64(txn.state_update.previous_state_hash)
                    txn.state_update.message_hash = self._to_base64(txn.state_update.message_hash)

                    contract.contract_code_hash = self._to_base64(contract.contract_code_hash)

                    if not signature:
                        txn.contract_enclave_signature = sign_ccl_transaction(
                            txn,
                            contract,
                            self._enclave_signing_private_key
                        )

                    if json_dict['verb'] == 'initialize':
                        # generate PDO signature normally done using one time transaction signing key
                        # to simplify test automation assume reuse signing key used to register the contract
                        txn.pdo_signature = secp256k1_sign(
                            make_ccl_transaction_pdo_hash_input(
                                txn,
                                contract),
                            contract_creator_private_key
                        )

                    if self._verbose:
                        print("Updated CCL Transaction:")
                        PdoDbgDump().dump_ccl_transaction(txn)
                        PdoDbgDump().dump_ccl_transaction_protobuf_message_to_json(txn)

                    result = self.connect.send_transaction(txn.SerializeToString(), address_family, wait=wait)
                    if self._verbose:
                        print(result)

                    print("OK")
                    return

        try:
            if self.connect.execute_json_transaction(json_input, address_family, wait, PdoCliException, self._verbose):
                print("OK")
            else:
                print("Error")
        except PdoCliException as e:
            print(e)
            print("Error")
        except TypeError as err:
            print("missing or invalid key:", err)
            print("Error")

    def execute_show_request(self, type, value, wait):
        if type == 'address':
            prefix = value[0:6]
            if prefix == self.connect.get_enclave_prefix():
                pdo_state_type = PdoContractEnclaveInfo
                dump = PdoDbgDump().dump_contract_enclave_state
                prompt = "\nEnclave info for address {}:".format(value)
            elif prefix == self.connect.get_contract_prefix():
                pdo_state_type = PdoContractInfo
                dump = PdoDbgDump().dump_contract_state
                prompt = "\nContract info for address {}:".format(value)
            elif prefix == self.connect.get_ccl_info_prefix():
                pdo_state_type = CCL_ContractInformation
                dump = PdoDbgDump().dump_ccl_info
                prompt = "\nCCL info for address {}:".format(value)
            elif prefix == self.connect.get_ccl_state_prefix():
                pdo_state_type = CCL_ContractState
                dump = PdoDbgDump().dump_ccl_state
                prompt = "\nCCL state for address {}:".format(value)
            else:
                raise PdoCliException("It is not a PD0 namespaces prefix '{}'".format(prefix))

            try:
                info = self.connect.get_state(value, pdo_state_type, value)
                dump(info, prompt)
            except BaseException as err:
                print(err)
            except ClientConnectException as err:
                print(err)

        elif type == 'enclave':
            if self._verbose:
                print("Enclave as dictionary:\n{}\n".format(self.connect.get_enclave_dict(value)))
            state = self._get_enclave_state(value)
            PdoDbgDump().dump_contract_enclave_state(
                state,
                "\nPDO Enclave Info for {}".format(self.connect.get_enclave_address(value)))
        elif type == 'contract':
            if self._verbose:
                print("Contract as dictionary:\n{}\n".format(self.connect.get_contract_dict(value)))
            state = self._get_contract_state(value)
            PdoDbgDump().dump_contract_state(
                state,
                "\nPDO Contract Info for {}".format(self.connect.get_contract_address(value)))
        elif type == 'ccl':
            if self._verbose:
                print("CCL Info as dictionary:\n{}\n".format(self.connect.get_ccl_info_dict(value)))
            info = self._get_ccl_info_state(value)
            PdoDbgDump().dump_ccl_info(
                info,
                "\nPDO CCL Info for {}".format(self.connect.get_ccl_info_address(value)))
            if info.current_state.state_hash and info.current_state.contract_id:
                if self._verbose:
                    print("CCL State as dictionary:\n{}\n".format(self.connect.get_ccl_state_dict(
                        value,
                        info.current_state.state_hash)))
                state = self._get_ccl_state_state(value, info.current_state.state_hash)
                PdoDbgDump().dump_ccl_state(
                    state,
                    "\nPDO CCL State for {}".format(self.connect.get_ccl_state_address(
                        value,
                        info.current_state.state_hash)))
        elif type == 'ccl-history':
            info = self._get_ccl_info_state(value)
            PdoDbgDump().dump_ccl_info(
                info,
                "\nPDO CCL Info for {}".format(self.connect.get_ccl_info_address(value)))
            state_hash = info.current_state.state_hash
            while state_hash:
                state = self._get_ccl_state_state(value, state_hash)
                PdoDbgDump().dump_ccl_state(
                    state,
                    "\nPDO CCL State for {}".format(self.connect.get_ccl_state_address(value, state_hash)))
                state_hash = state.state_update.previous_state_hash
        elif type == 'ccl-state':
            value_list = value.split(':')
            state = self._get_ccl_state_state(value_list[0], value_list[1])
            PdoDbgDump().dump_ccl_state(
                state,
                "\nPDO CCL State for {}".format(self.connect.get_ccl_state_address(
                    value_list[0],
                    value_list[1])))
        elif type == 'setting':
            if value == "basenames":
                setting_name = self.connect.get_valid_basenames_setting_name()
            elif value == "measurements":
                setting_name = self.connect.get_valid_measurements_setting_name()
            elif value == "report-public-key":
                setting_name = self.connect.get_report_public_key_setting_name()
            else:
                setting_name = value

            if self._verbose:
                print("value:", value)

            self._show_config_setting(setting_name)
        else:
            raise PdoCliException("invalid PD0 state type '{}'".format(type))

        return "OK"

    def _make_enclave_id_for_list(self, enclave_info):
        if len(enclave_info.verifying_key) > 40:
            return "{}...".format(enclave_info.verifying_key[0:40])
        else:
            return enclave_info.verifying_key[0:40]

    def _make_contract_id_for_list(self, contract_info):
        if len(contract_info.contract_id) > 40:
            return "{}...".format(contract_info.contract_id[0:40])
        else:
            return contract_info.contract_id[0:40]

    def _make_ccl_info_id_for_list(self, ccl_info):
        if len(ccl_info.contract_id) > 40:
            return "{}...".format(ccl_info.contract_id[0:40])
        else:
            return ccl_info.contract_id[0:40]

    def _make_ccl_state_id_for_list(self, ccl_state):
        if len(ccl_state.state_update.contract_id) > 18:
            contract_id_part = "{}...".format(ccl_state.state_update.contract_id[0:18])
        else:
            contract_id_part = ccl_state.state_update.contract_id[0:18]

        if len(ccl_state.state_update.current_state_hash) > 18:
            state_hash_part = "{}...".format(ccl_state.state_update.current_state_hash[0:18])
        else:
            state_hash_part = ccl_state.state_update.current_state_hash[0:18]

        return "{0}:{1}".format(contract_id_part, state_hash_part)

    def execute_list_request(self, namespace_name, details, page_size, max_entries, wait=None):
        pdo_state_type = make_id = dump = None
        prefix = ""

        if namespace_name == 'enclave':
            pdo_state_type = PdoContractEnclaveInfo
            prefix = self.connect.get_enclave_prefix()
            make_id = self._make_enclave_id_for_list
            if details:
                dump = PdoDbgDump().dump_contract_enclave_state
            print("\nEnclaves list:")
        elif namespace_name == 'contract':
            pdo_state_type = PdoContractInfo
            prefix = self.connect.get_contract_prefix()
            make_id = self._make_contract_id_for_list
            if details:
                dump = PdoDbgDump().dump_contract_state
            print("\nContracts list:")
        elif namespace_name == 'ccl-info':
            pdo_state_type = CCL_ContractInformation
            prefix = self.connect.get_ccl_info_prefix()
            make_id = self._make_ccl_info_id_for_list
            if details:
                dump = PdoDbgDump().dump_ccl_info
            print("\nCCL information list:")
        elif namespace_name == 'ccl-state':
            pdo_state_type = CCL_ContractState
            prefix = self.connect.get_ccl_state_prefix()
            make_id = self._make_ccl_state_id_for_list
            if details:
                dump = PdoDbgDump().dump_ccl_state
            print("\nCCl states list:")
        elif namespace_name == 'settings':
            print("\nSawtooth settings:")
            self._show_config_setting_list()
        else:
            raise PdoCliException(
                "Invalid PD0 family type '{}'. Must be one of enclave, contract, ccl-info, or ccl-state".format(
                    namespace_name))

        if prefix:
            self._execute_list_request(namespace_name, prefix, pdo_state_type, make_id, dump, page_size, max_entries)

        return "\nOk"

    def _execute_list_request(self, namespace_name, prefix, pdo_state_type, make_id, dump, page_size, max_entries):
        if page_size != 0:
            next_url = "state?address={0}&limit={1}".format(prefix, page_size)
        else:
            next_url = "state?address={0}".format(prefix)
        count = 0
        try:
            while next_url and count < max_entries:
                result = self.connect.send_request(next_url, name=prefix)
                json = yaml.safe_load(result)
                try:
                    next_url = ""
                    paging = json["paging"]
                    next_url = paging["next"]
                    domain_end = next_url.find("/", 7)
                    next_url = next_url[(domain_end + 1):]
                except:
                    pass

                data = json["data"]
                for entry in data:
                    decoded_data = base64.b64decode(entry["data"])
                    address = entry["address"]
                    count += 1
                    state = pdo_state_type()
                    state.ParseFromString(decoded_data)
                    if dump:
                        prompt = "\n{0} [{1}] for address {2}:".format(namespace_name, count, address)
                        dump(state, prompt)
                    else:
                        print("{0}: {1}  {2}".format(count, address, make_id(state)))
                    if count >= max_entries:
                        break

        except ClientConnectException as err:
            print(err)
            return "State list not found"
        except BaseException:
            print("Failed to parse result")
            return "Failed to parse result"

        return "OK"

    def _del_enclave_callback(self, enclave_state, wait):
        txn = PdoContractEnclaveTransaction()
        txn.verb = 'delete'
        txn.verifying_key = enclave_state.verifying_key

        self._send_enclave_transaction(txn, wait)

    def _del_contract_callback(self, contract_state, wait):
        txn = PdoContractTransaction()
        txn.verb = 'delete'
        txn.contract_id = contract_state.contract_id

        self._send_contract_transaction(txn, wait)

    def _del_ccl_state_callback(self, ccl_state, wait):
        txn = CCL_TransactionPayload()
        txn.verb = 'delete'

        dependency = txn.state_update.dependency_list.add()
        dependency.contract_id = ccl_state.state_update.contract_id
        dependency.state_hash = ccl_state.state_update.current_state_hash

        self._send_ccl_transaction(txn, wait)

    def _del_ccl_info_callback(self, ccl_info, wait):
        txn = CCL_TransactionPayload()
        txn.verb = 'delete'
        txn.state_update.contract_id = ccl_info.current_state.contract_id

        self._send_ccl_transaction(txn, wait)

    def _execute_delete_request(self, prefix, pdo_state_type, make_id, delete_callaback, wait):
        try:
            count = 0
            while count < 10:
                count += 1
                result = self.connect.send_request("state?address={}".format(prefix), name=prefix)
                json = yaml.safe_load(result)
                data = json["data"]
                delete_count = 0
                for entry in data:
                    decoded_data = base64.b64decode(entry["data"])
                    address = entry["address"]
                    if address in address_skip_list:
                        print("Skipping: {0}".format(address))
                    else:
                        state = pdo_state_type()
                        state.ParseFromString(decoded_data)
                        delete_count += 1
                        print("Deleting: {0}  {1}".format(address, make_id(state)))
                        delete_callaback(state, wait)
                if delete_count == 0:
                    break

        except ClientConnectException as err:
            print(err)
            return "State list not found"
        except BaseException:
            print("Failed to parse result")
            return "Failed to parse result"

        return "OK"

    def execute_delete_request(self, family, wait):
        if family == 'enclave':
            pdo_state_type = PdoContractEnclaveInfo
            prefix = self.connect.get_enclave_prefix()
            make_id = self._make_enclave_id_for_list
            delete_callback = self._del_enclave_callback
            print("\nDeleting enclaves:")
        elif family == 'contract':
            pdo_state_type = PdoContractInfo
            prefix = self.connect.get_contract_prefix()
            make_id = self._make_contract_id_for_list
            delete_callback = self._del_contract_callback
            print("\nDeleting contracts:")
        elif family == 'ccl-info':
            pdo_state_type = CCL_ContractInformation
            prefix = self.connect.get_ccl_info_prefix()
            make_id = self._make_ccl_info_id_for_list
            delete_callback = self._del_ccl_info_callback
            print("\nDeleting ccl info entries:")
        elif family == 'ccl-state':
            pdo_state_type = CCL_ContractState
            prefix = self.connect.get_ccl_state_prefix()
            make_id = self._make_ccl_state_id_for_list
            delete_callback = self._del_ccl_state_callback
            print("\nDeleting ccl state entries:")
        else:
            raise PdoCliException(
                "Invalid PD0 family type '{}'. Must be one of enclave, contract, ccl-info, or ccl-state".format(family))

        self._execute_delete_request(prefix, pdo_state_type, make_id, delete_callback, wait)
        return "\nOk"

    def generate_test_enclave_info_request(self):
        public_signer_key = self.connect.get_signer_public_key_as_hex()
        txn = CreateTestEnclavePayload().create_test_enclave(public_signer_key)
        PdoDbgDump().dump_enclave_transaction_protobuf_message_to_json(
            txn,
            self.connect.get_enclave_registry_family_name()
        )

        return "OK"

    def generate_signing_key_request(self):
        private_key_as_hex = generate_private_key_as_hex()
        print("\nPrivate key: '{0}'".format(private_key_as_hex))
        print("\nPublic key: '{0}'".format(get_public_key_as_hex(private_key_as_hex)))
        print()
        return "OK"

    def execute_ping(self, wait):
        # generate dummy private enclave key
        self._enclave_signing_private_key = generate_private_key_as_hex()

        # use time stamp to ensure submission uniqueness
        p2 = str(time.time())
        ping_json = self._ping_transcation_base + p2 + '"]\n}'

        print("Executing a contract register transaction... it may take up to 2 minutes")
        self.execute_json_transaction(ping_json, "", wait)

        print("Retrieving a contract registry entry...")
        try:
            contract = self._find_contract_id(provisioning_id_filter=p2)
            if p2 in contract.provisioning_service_ids:
                print("\nPing successful\n")
            else:
                print("\nPing failed\n")
                return
        except PdoCliException as e:
            print("PdoCliException:", e)
            print("\nPing failed\n")
            return
        except:
            print("\nPing failed\n")
            return

        try:
            print("Removing the added contract registry entry...")
            txn = PdoContractTransaction()
            txn.verb = "delete"
            txn.contract_id = contract.contract_id
            self._send_contract_transaction(txn, wait)
        except:
            pass

        try:
            contract = self._get_contract_state(contract.contract_id, True)
            if contract.contract_id:
                print("Removal of the contract failed, likely, because transcation processor is running in debug OFF mode")
            else:
                print("Removal of the contract succeeded")
        except:
            print("Removal of the contract succeeded")
            return

    def execute_set_setting(self, key, value, wait):
        print("Set setting command:")
        print("\tkey: {0}".format(key))
        print("\tvalue: {0}".format(value))
        print("\twait: {0}".format(wait))

        payload = self._create_propose_payload(key, value)
        inputs = self._config_inputs(key)
        outputs = self._config_outputs(key)

        response = self.connect.send_transaction(
            payload,
            "sawtooth_settings",
            wait=wait,
            transaction_output_list=outputs,
            transaction_input_list=inputs,
            verbose=self._verbose
        )

        print("response:", response)
        return "OK"

    def _create_propose_payload(self, setting_key, setting_value):
        # Creates an individual sawtooth_settings payload for the given key and value

        nonce = str(datetime.datetime.utcnow().timestamp())
        proposal = SettingProposal(
            setting=setting_key,
            value=setting_value,
            nonce=nonce)
        payload = SettingsPayload(
            data=proposal.SerializeToString(),
            action=SettingsPayload.PROPOSE)

        return payload.SerializeToString()

    def _config_inputs(self, key):
        # Creates the list of inputs for a sawtooth_settings transaction

        return [
            self._key_to_address('sawtooth.settings.vote.proposals'),
            self._key_to_address('sawtooth.settings.vote.authorized_keys'),
            self._key_to_address('sawtooth.settings.vote.approval_threshold'),
            self._key_to_address(key)
        ]

    def _config_outputs(self, key):
        # Creates the list of outputs for a sawtooth_settings transaction

        return [
            self._key_to_address('sawtooth.settings.vote.proposals'),
            self._key_to_address(key)
        ]

    def _short_hash(self, in_str):
        return short_hash(in_str.encode())

    def _key_to_address(self, key):
        """Creates the state address for a given setting key.
        """
        key_parts = key.split('.', maxsplit=_MAX_KEY_PARTS - 1)
        key_parts.extend([''] * (_MAX_KEY_PARTS - len(key_parts)))

        return SETTINGS_NAMESPACE + ''.join(self._short_hash(x) for x in key_parts)

