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
stat_logger = logger.getChild('stats')

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
    def __cache_filename__(cls, contract_id, state_hash, data_dir) :
        """
        state_hash = base64 encoded

        """
        contract_id = ContractState.safe_filename(contract_id)
        state_hash = ContractState.safe_filename(state_hash)

        subdirectory = os.path.join(cls.__path__, contract_id, state_hash[0:2])
        return putils.build_file_name(state_hash, data_dir, subdirectory, cls.__extension__)

    # --------------------------------------------------
    @classmethod
    def __cache_data_block__(cls, contract_id, raw_data, data_dir = None) :
        """
        save a data block into the local cache

        :param contract_id str: contract identifier, base64 encoded
        :param raw_data str: base64 encoded string
        """

        state_hash = ContractState.compute_hash(raw_data, encoding='b64')
        filename = ContractState.__cache_filename__(contract_id, state_hash, data_dir)
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
    def __read_data_block_from_cache__(cls, contract_id, state_hash, data_dir = None) :
        """
        read a data block from the local cache

        :param contract_id str: contract identifier, base64 encoded
        :param state_hash str: b64 encoded string
        """

        filename = ContractState.__cache_filename__(contract_id, state_hash, data_dir)

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
    def __push_block_to_eservice__(eservice, contract_id, state_hash, data_dir = None) :
        """
        ensure that a particular block is stored in the eservice

        :param eservice EnclaveServiceClient object:
        :param contract_id str: contract identifier
        :param state_hash string: base64 encoded hash of the block
        """

        logger.debug('ensure block %s is stored in the eservice', state_hash)

        # check to see if the eservice already has the block
        if eservice.block_store_head(state_hash) > 0 :
            return False

        raw_data = ContractState.__read_data_block_from_cache__(contract_id, state_hash, data_dir)
        if raw_data is None :
            raise Exception('unable to locate required block; {}'.format(state_hash))

        eservice.block_store_put(state_hash, raw_data)

        logger.debug('sent block %s to eservice', state_hash)
        return True

    @staticmethod
    def __push_blocks_to_eservice__(eservice, contract_id, block_ids, data_dir = None) :
        """
        ensure that required blocks are stored in the storage service

        :param eservice EnclaveServiceClient object:
        :param contract_id str: contract identifier
        :param block_ids list of strings: base64 encoded hash of the block
        """
        # check to see which blocks need to be pushed
        blocks_to_push = []
        blocks_to_extend = []
        block_status_list = eservice.check_blocks(block_ids, encoding='b64')
        for block_status in block_status_list :
            # if the size is 0 then the block is unknown to the storage service
            if block_status['size'] == 0 :
                blocks_to_push.append(block_status['block_id'])
            # if the expiration is nearing, then add to the list to extend, the
            # policy here is to extend if the block is within 5 seconds of expiring
            elif block_status['expiration'] < 5 :
                blocks_to_extend.append(block_status['block_id'])

        def block_data_generator(contract_id, block_ids, data_dir) :
            for block_id in block_ids :
                raw_data = ContractState.__read_data_block_from_cache__(contract_id, block_id, data_dir)
                if raw_data is None :
                    raise Exception('unable to locate required block; {}'.format(block_id))
                yield raw_data

        block_data_list = block_data_generator(contract_id, blocks_to_push, data_dir)
        block_store_list = eservice.store_blocks(block_data_list, expiration=60, encoding='b64')
        if block_store_list is None :
            raise Exception('failed to push blocks to eservice')

        return len(blocks_to_push)

    # --------------------------------------------------
    @classmethod
    def __pull_block_from_eservice__(cls, eservice, contract_id, state_hash, data_dir = None) :
        """
        ensure that a block is cached locally

        :param eservice EnclaveServiceClient object:
        :param contract_id str: contract identifier
        :param state_hash string: base64 encoded hash of the block
        """

        # check to see if the eservice already has the block
        logger.debug('ensure block %s is stored in the local cache', state_hash)

        # first see if the block is already in the cache
        filename = ContractState.__cache_filename__(contract_id, state_hash, data_dir)
        if os.path.isfile(filename) :
            return False

        # it is not in the cache so grab it from the eservice
        raw_data = eservice.block_store_get(state_hash)
        if raw_data :
            # since we don't really trust the eservice, make sure that the
            # block it sent us is really the one that we were supposed to get
            if ContractState.compute_hash(raw_data, encoding='b64') != state_hash :
                raise Exception('invalid block returned from eservice')

            ContractState.__cache_data_block__(contract_id, raw_data, data_dir)

        logger.debug('retrieved block %s from eservice', state_hash)
        return True

    # --------------------------------------------------
    @classmethod
    def read_from_cache(cls, contract_id, state_hash, data_dir = None) :
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
    def push_state_to_eservice(self, eservice, data_dir = None) :
        """
        push the blocks associated with the state to the eservice

        :param eservice EnclaveServiceClient object:
        """

        if not self.encrypted_state :
            return

        block_ids = [ self.get_state_hash(encoding='b64') ]
        block_ids.extend(self.component_block_ids)

        pushed_blocks = ContractState.__push_blocks_to_eservice__(eservice, block_ids, data_dir)
        stat_logger.debug('state length is %d, pushed %d new blocks', len(self.component_block_ids), pushed_blocks)

    # --------------------------------------------------
    def pull_state_from_eservice(self, eservice, data_dir = None) :
        """
        push the blocks associated with the state to the eservice

        :param eservice EnclaveServiceClient object:
        """

        if not self.encrypted_state :
            return

        pulled_blocks = 0

        b64_block_id = self.get_state_hash(encoding='b64')
        if ContractState.__pull_block_from_eservice__(eservice, self.contract_id, b64_block_id, data_dir) :
            pulled_blocks += 1

        for b64_block_id in self.component_block_ids :
            if ContractState.__pull_block_from_eservice__(eservice, self.contract_id, b64_block_id, data_dir) :
                pulled_blocks += 1

        stat_logger.debug('state length is %d, pulled %d new blocks', len(self.component_block_ids), pulled_blocks)

    # --------------------------------------------------
    def save_to_cache(self, data_dir = None) :
        ContractState.__cache_data_block__(self.contract_id, self.encrypted_state, data_dir)
