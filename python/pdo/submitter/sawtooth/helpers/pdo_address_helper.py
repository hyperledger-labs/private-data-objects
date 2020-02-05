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

import hashlib


# Constants to be used when constructing config namespace addresses
_CONFIG_NAMESPACE = '000000'
_CONFIG_MAX_KEY_PARTS = 4
_CONFIG_ADDRESS_PART_SIZE = 16


def _config_short_hash(byte_str):
    # Computes the SHA 256 hash and truncates to be the length
    # of an address part (see _config_key_to_address for information on
    return hashlib.sha256(byte_str).hexdigest()[:_CONFIG_ADDRESS_PART_SIZE]


def short_hash(byte_str):
    return _config_short_hash(byte_str)


_CONFIG_ADDRESS_PADDING = _config_short_hash(byte_str=b'')


class PdoAddressHelper:
    def __init__(self):
        self._enclave_prefix = \
            self._sha512(self.get_enclave_namespace().encode('utf-8'))[0:6]
        self._contract_prefix = \
            self._sha512(self.get_contract_namespace().encode('utf-8'))[0:6]
        self._ccl_info_prefix = \
            self._sha512(self.get_ccl_state_namespace().encode('utf-8'))[0:6]
        self._ccl_state_prefix = \
            self._sha512(self.get_ccl_info_namespace().encode('utf-8'))[0:6]

    def get_enclave_namespace(self):
        return 'pdo_contract_enclave_registry'

    def get_contract_namespace(self):
        return 'pdo_contract_instance_registry'

    def get_ccl_state_namespace(self):
        return 'pdo_contract_state_registry'

    def get_ccl_info_namespace(self):
        return 'pdo_contract_information_registry'

    def _sha512(self, data):
        return hashlib.sha512(data).hexdigest()

    def get_enclave_prefix(self):
        return self._enclave_prefix

    def get_contract_prefix(self):
        return self._contract_prefix

    def get_ccl_state_prefix(self):
        return self._ccl_state_prefix

    def get_ccl_info_prefix(self):
        return self._ccl_info_prefix

    def get_namespace_prefix(self, namespace):
        return self._sha512(namespace.encode('utf-8'))[0:6]

    def get_enclave_address(self, enclave_id):
        return self._enclave_prefix + \
               self._sha512(enclave_id.encode('utf-8'))[64:]

    def get_contract_address(self, contract_id):
        addr = self._contract_prefix + \
               self._sha512(contract_id.encode('utf-8'))[64:]
        return addr

    def get_ccl_info_address(self, contract_id):
        return self._ccl_info_prefix + \
               self._sha512(contract_id.encode('utf-8'))[64:]

    def get_ccl_state_address(self, contract_id, state_hash):
        return self._ccl_state_prefix + \
               self._sha512(contract_id.encode('utf-8'))[96:] + \
               self._sha512(state_hash.encode('utf-8'))[96:]

    def get_ccl_family_name(self):
        return 'ccl_contract'

    def get_contract_registry_family_name(self):
        return 'pdo_contract_instance_registry'

    def get_enclave_registry_family_name(self):
        return 'pdo_contract_enclave_registry'

    def get_report_public_key_setting_name(self):
        return 'pdo.test.registry.public_key'

    def get_valid_measurements_setting_name(self):
        return 'pdo.test.registry.measurements'

    def get_valid_basenames_setting_name(self):
        return 'pdo.test.registry.basenames'

    def get_setting_address(self, key):
        """Computes the address for the given setting key.

         Keys are broken into four parts, based on the dots in the string. For
         example, the key `a.b.c` address is computed based on `a`, `b`, `c` and
         padding. A longer key, for example `a.b.c.d.e`, is still
         broken into four parts, but the remaining pieces are in the last part:
         `a`, `b`, `c` and `d.e`.

         Each of these pieces has a short hash computed (the first
         _CONFIG_ADDRESS_PART_SIZE characters of its SHA256 hash in hex), and is
         joined into a single address, with the config namespace
         (_CONFIG_NAMESPACE) added at the beginning.

         Args:
             key (str): the setting key
         Returns:
             str: the computed address
         """
        # Split the key into _CONFIG_MAX_KEY_PARTS parts, maximum, compute the
        # short hash of each, and then pad if necessary
        key_parts = key.split('.', maxsplit=_CONFIG_MAX_KEY_PARTS - 1)
        addr_parts = [_config_short_hash(byte_str=x.encode()) for x in key_parts]
        addr_parts.extend(
            [_CONFIG_ADDRESS_PADDING] * (_CONFIG_MAX_KEY_PARTS - len(addr_parts)))
        return _CONFIG_NAMESPACE + ''.join(addr_parts)
