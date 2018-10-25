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
import pdo.common.utility as putils
import sawtooth.helpers.pdo_connect

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ContractState(object) :
    __path__ = '__state_cache__'
    __extension__ = '.ctx'

    # --------------------------------------------------
    @staticmethod
    def compute_hash(encrypted_state, encoding = 'raw') :
        """ compute the hash of the encrypted state
        """
        state_byte_array = crypto.base64_to_byte_array(encrypted_state)
        state_hash = crypto.compute_message_hash(state_byte_array)
        if encoding == 'raw' :
            return state_hash
        elif encoding == 'b64' :
            return crypto.byte_array_to_base64(state_hash)
        elif encoding == 'hex' :
            return crypto.byte_array_to_hex(state_hash)

        raise ValueError('unknown encoding; {}'.format(encoding))

    # --------------------------------------------------
    @staticmethod
    def safe_filename(b64name) :
        """the base64 encoding we use for contract_id and state_hash make
        them very poor file names; convert to hex for better behavior
        """
        decoded = crypto.base64_to_byte_array(b64name)
        encoded = crypto.byte_array_to_hex(decoded)
        return encoded[16:]

    # --------------------------------------------------
    @classmethod
    def read_from_cache(cls, contract_id, state_hash, data_dir = "./data") :
        contract_id = ContractState.safe_filename(contract_id)
        state_hash = ContractState.safe_filename(state_hash)

        cache_dir = os.path.join(data_dir, cls.__path__, contract_id)
        filename = putils.build_file_name(state_hash, cache_dir, cls.__extension__)

        try :
            logger.debug('load contract state from file %s', filename)
            with open(filename, "r") as statefile :
                state_info = json.load(statefile)
        except FileNotFoundError as fe :
            return None
        except Exception as e :
            logger.info('error reading state; %s', str(e))
            raise Exception('failed to read state from cache; {}'.format(contract_id))

        return cls(state_info['ContractID'], state_info.get('EncryptedState'))

    # --------------------------------------------------
    @staticmethod
    def get_current_state_hash(ledger_config, contract_id) :
        """Retrieve the current state hash for the contract

        :param ledger_config dictionary: ledger configuration that must contain 'LedgerURL'
        :param contract_id str: contract identifier
        """
        client = sawtooth.helpers.pdo_connect.PdoRegistryHelper(ledger_config['LedgerURL'])

        try :
            # what is returned when the contract has been created but
            # state has not been initialized? need to detect this and
            # return some kind of "not found" exception
            contract_state_info = client.get_ccl_info_dict(contract_id)
            current_state_hash = contract_state_info['current_state']['state_hash']
        except Exception as e :
            logger.info('error getting state hash; %s', str(e))
            raise Exception('failed to retrieve contract state hash; {}'.format(contract_id))

        return current_state_hash

    # --------------------------------------------------
    @classmethod
    def get_from_ledger(cls, ledger_config, contract_id, current_state_hash = None) :
        if current_state_hash is None :
            current_state_hash = ContractState.get_current_state_hash(ledger_config, contract_id)

        client = sawtooth.helpers.pdo_connect.PdoRegistryHelper(ledger_config['LedgerURL'])

        try :
            contract_state = client.get_ccl_state_dict(contract_id, current_state_hash)
            encrypted_state = contract_state['state_update']['encrypted_state']
        except Exception as e :
            logger.info('error getting state; %s', str(e))
            raise Exception('failed to retrieve contract state; {}', contract_id)

        return cls(contract_id, encrypted_state = encrypted_state)

    # --------------------------------------------------
    @classmethod
    def create_new_state(cls, contract_id) :
        return cls(contract_id)

    # --------------------------------------------------
    def __init__(self, contract_id, encrypted_state = '') :
        self.contract_id = contract_id
        self.encrypted_state = encrypted_state

    # --------------------------------------------------
    def getStateHash(self, encoding='raw') :
        """
        gets the hash of the encrypted state if it is non-empty
        returns None if no encrypted state exists
        """
        if self.encrypted_state:
            return ContractState.compute_hash(self.encrypted_state, encoding)
        return None

    # --------------------------------------------------
    def serializeForInvokation(self) :
        """
        serializes the elements needed by the contract enclave to invoke the contract
        does not include the encrypted state itself
        """
        result = dict()
        result['ContractID'] = self.contract_id
        if self.encrypted_state :
            result['StateHash'] = ContractState.compute_hash(self.encrypted_state, encoding='b64')

        return result

    # --------------------------------------------------
    def serialize(self) :
        """
        serializes the entire state (including the state itself) for storage
        """
        result = dict()
        result['ContractID'] = self.contract_id
        if self.encrypted_state :
            result['EncryptedState'] = self.encrypted_state
            result['StateHash'] = ContractState.compute_hash(self.encrypted_state, encoding='b64')

        return result

    # --------------------------------------------------
    def save_to_cache(self, data_dir = "./data") :
        contract_id = ContractState.safe_filename(self.contract_id)
        state_hash = ContractState.compute_hash(self.encrypted_state, encoding='b64')
        state_hash = ContractState.safe_filename(state_hash)

        cache_dir = os.path.join(data_dir, self.__path__, contract_id)
        filename = putils.build_file_name(state_hash, cache_dir, '.ctx')
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))

        try :
            logger.debug('save contract state to file %s', filename)
            with open(filename, 'w') as statefile :
                json.dump(self.serialize(), statefile)
        except Exception as e :
            logger.info('failed to save state; %s', str(e))
            raise Exception('unable to cache state {}'.format(filename))
