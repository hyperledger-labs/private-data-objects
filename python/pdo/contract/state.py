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
    def __cache_data_block__(cls, contract_id, raw_data, data_dir = "./data") :
        """
        save a data block into the local cache

        :param contract_id str: contract identifier, base64 encoded
        :param raw_data str: base64 encoded string
        """

        contract_id = ContractState.safe_filename(contract_id)
        state_hash = ContractState.compute_hash(raw_data, encoding='b64')
        state_hash = ContractState.safe_filename(state_hash)

        cache_dir = os.path.join(data_dir, cls.__path__, contract_id)
        filename = putils.build_file_name(state_hash, cache_dir, '.ctx')
        if not os.path.exists(os.path.dirname(filename)):
            os.makedirs(os.path.dirname(filename))

        try :
            logger.debug('save state block to file %s', filename)
            with open(filename, 'w') as statefile :
                statefile.write(raw_data)
                # json.dump(, statefile)
        except Exception as e :
            logger.info('failed to save state; %s', str(e))
            raise Exception('unable to cache state {}'.format(filename))

    # --------------------------------------------------
    @classmethod
    def __read_data_block_from_cache__(cls, contract_id, state_hash, data_dir = "./data") :
        """
        read a data block from the local cache

        :param contract_id str: contract identifier, base64 encoded
        :param state_hash str: b64 encoded string
        """

        contract_id = ContractState.safe_filename(contract_id)
        state_hash = ContractState.safe_filename(state_hash)

        cache_dir = os.path.join(data_dir, cls.__path__, contract_id)
        filename = putils.build_file_name(state_hash, cache_dir, cls.__extension__)

        try :
            logger.debug('read state block from file %s', filename)
            with open(filename, "r") as statefile :
                raw_data = statefile.read()
        except FileNotFoundError as fe :
            logger.error('file not found; %s', filename)
            return None
        except Exception as e :
            logger.info('error reading state; %s', str(e))
            raise Exception('failed to read state from cache; {}'.format(contract_id))

        return raw_data

    # --------------------------------------------------
    @staticmethod
    def __push_block_to_eservice__(eservice, contract_id, state_hash, data_dir = "./data") :
        """
        ensure that a particular block is stored in the eservice

        :param eservice EnclaveServiceClient object:
        :param contract_id str: contract identifier
        :param state_hash string: base64 encoded hash of the block
        """

        logger.debug('ensure block %s is stored in the eservice', state_hash)

        # check to see if the eservice already has the block
        if eservice.block_store_head(state_hash) > 0 :
            return

        raw_data = ContractState.__read_data_block_from_cache__(contract_id, state_hash, data_dir)
        if raw_data is None :
            raise Exception('unable to locate required block; {}'.format(state_hash))

        if not eservice.block_store_put(state_hash, raw_data) :
            raise Exception('failed to push block to eservice; {}'.format(state_hash))

        logger.debug('sent block %s to eservice', state_hash)

    # --------------------------------------------------
    @classmethod
    def __cache_block_from_eservice__(cls, eservice, contract_id, state_hash, data_dir = "./data") :
        """
        ensure that a block is cached locally

        :param eservice EnclaveServiceClient object:
        :param contract_id str: contract identifier
        :param state_hash string: base64 encoded hash of the block
        """

        # check to see if the eservice already has the block
        logger.debug('ensure block %s is stored in the local cache', state_hash)

        # first see if the block is already in the cache
        safe_contract_id = ContractState.safe_filename(contract_id)
        safe_state_hash = ContractState.safe_filename(state_hash)

        cache_dir = os.path.join(data_dir, cls.__path__, safe_contract_id)
        filename = putils.build_file_name(safe_state_hash, cache_dir, cls.__extension__)
        if os.path.isfile(filename) :
            return

        # it is not in the cache so grab it from the eservice
        raw_data = eservice.block_store_get(state_hash)
        if raw_data :
            # since we don't really trust the eservice, make sure that the
            # block it sent us is really the one that we were supposed to get
            if ContractState.compute_hash(raw_data, encoding='b64') != state_hash :
                raise Exception('invalid block returned from eservice')

            ContractState.__cache_data_block__(contract_id, raw_data, data_dir)

        logger.debug('sent block %s to eservice', state_hash)


    # --------------------------------------------------
    @classmethod
    def read_from_cache(cls, contract_id, state_hash, data_dir = "./data") :
        """
        read a block from the local cache and create contract state for it

        :param contract_id str: contract identifier, base64 encoded
        :param state_hash str: b64 encoded string
        """
        raw_data = ContractState.__read_data_block_from_cache__(contract_id, state_hash, data_dir)
        return cls(contract_id, raw_data)

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
        self.update_state(encrypted_state)

    # --------------------------------------------------
    def update_state(self, encrypted_state) :
        self.encrypted_state = encrypted_state
        self.component_block_ids = []

        if self.encrypted_state :
            b64_decoded_byte_array = crypto.base64_to_byte_array(self.encrypted_state)
            b64_decoded_string = crypto.byte_array_to_string(b64_decoded_byte_array).rstrip('\0')
            json_main_state_block = json.loads(b64_decoded_string)
            self.component_block_ids = json_main_state_block['BlockIds']

    # --------------------------------------------------
    def get_state_hash(self, encoding='raw') :
        """
        gets the hash of the encrypted state if it is non-empty
        returns None if no encrypted state exists
        """
        if self.encrypted_state:
            return ContractState.compute_hash(self.encrypted_state, encoding)
        return None

    # --------------------------------------------------
    def serialize_for_invocation(self) :
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
    def push_state_to_eservice(self, eservice, data_dir = "./data") :
        """
        push the blocks associated with the state to the eservice

        :param eservice EnclaveServiceClient object:
        """

        if self.encrypted_state is '' :
            return

        ContractState.__push_block_to_eservice__(eservice, self.contract_id, self.get_state_hash(encoding='b64'), data_dir)

        for b64_block_id in self.component_block_ids :
            ContractState.__push_block_to_eservice__(eservice, self.contract_id, b64_block_id, data_dir)

    # --------------------------------------------------
    def pull_state_from_eservice(self, eservice, data_dir = "./data") :
        """
        push the blocks associated with the state to the eservice

        :param eservice EnclaveServiceClient object:
        """

        if self.encrypted_state is '' :
            return

        ContractState.__cache_block_from_eservice__(eservice, self.contract_id, self.get_state_hash(encoding='b64'), data_dir)

        for b64_block_id in self.component_block_ids :
            ContractState.__cache_block_from_eservice__(eservice, self.contract_id, b64_block_id, data_dir)

    # --------------------------------------------------
    def save_to_cache(self, data_dir = "./data") :
        ContractState.__cache_data_block__(self.contract_id, self.encrypted_state, data_dir)
