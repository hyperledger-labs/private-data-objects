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
    def compute_hash(raw_state, encoding = 'raw') :
        """ compute the hash of the contract state

        :param raw_state string: root block of contract state, json string
        """
        state_hash = crypto.compute_message_hash(raw_state)
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
        return encoded[:16]

    # --------------------------------------------------
    @staticmethod
    def block_data_generator(contract_id, block_ids, data_dir) :
        for block_id in block_ids :
            raw_data = ContractState.__read_data_block_from_cache__(contract_id, block_id, data_dir)
            if raw_data is None :
                raise Exception('unable to locate required block; {}'.format(block_id))
            yield raw_data

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
            with open(filename, 'wb') as statefile :
                statefile.write(raw_data)
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
            with open(filename, "rb") as statefile :
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
        block_status_list = eservice.check_blocks(block_ids)
        for block_status in block_status_list :
            # if the size is 0 then the block is unknown to the storage service
            if block_status['size'] == 0 :
                blocks_to_push.append(block_status['block_id'])
            # if the expiration is nearing, then add to the list to extend, the
            # policy here is to extend if the block is within 5 seconds of expiring
            elif block_status['expiration'] < 5 :
                blocks_to_extend.append(block_status['block_id'])

        # there is currently no operation to simply extend the expiration of
        # an existing block, so for now just add the blocks to extend onto
        # the end of the blocks to push
        blocks_to_push += blocks_to_extend

        if len(blocks_to_push) == 0 :
            logger.debug('enclave service has state')
            return 0

        logger.debug('push blocks to service: %s', blocks_to_push)

        block_data_list = ContractState.block_data_generator(contract_id, blocks_to_push, data_dir)
        block_store_list = eservice.store_blocks(block_data_list, expiration=60)
        if block_store_list is None :
            raise Exception('failed to push blocks to eservice')

        return len(blocks_to_push)

    # --------------------------------------------------
    @classmethod
    def __pull_blocks_from_eservice__(cls, eservice, contract_id, block_ids, data_dir = None) :
        """
        ensure that a list of blocks is cached locally

        :param eservice EnclaveServiceClient object:
        :param contract_id str: contract identifier
        :param block_ids list: base64 encoded hash of the blocks required
        """

        # first see if the block is already in the cache
        blocks_to_pull = set()
        for block_id in block_ids :
            filename = ContractState.__cache_filename__(contract_id, block_id, data_dir)
            if not os.path.isfile(filename) :
                blocks_to_pull.add(block_id)

        block_count = len(blocks_to_pull)
        if block_count == 0 :
            logger.debug('no blocks to pull')
            logger.info("Pulled 0 new blocks after contract update")
            return 0

        # it is not in the cache so grab it from the eservice
        block_data_iterator = eservice.get_blocks(list(blocks_to_pull))

        # since we don't really trust the eservice, make sure that the
        # block it sent us is really the one that we were supposed to get
        for raw_block in block_data_iterator :
            raw_block_hash = ContractState.compute_hash(raw_block, encoding='b64')
            if raw_block_hash not in blocks_to_pull :
                raise Exception('unknown block pulled from storage service; {0}'.format(raw_block_hash))

            ContractState.__cache_data_block__(contract_id, raw_block, data_dir)
            blocks_to_pull.remove(raw_block_hash)

        # make sure that the storage service gave us all the blocks we asked for
        if len(blocks_to_pull) != 0 :
            raise Exception('failed to pull blocks from storage service; %s', list(blocks_to_pull))

        logger.info("Pulled %d new blocks after contract update", block_count + 1) # + 1 to add the root block

        return len(blocks_to_pull)

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
            contract_info = client.get_ccl_state_dict(contract_id, current_state_hash)
            raw_state = contract_info['state_update']['encrypted_state']
        except Exception as e :
            logger.info('error getting state; %s', str(e))
            raise Exception('failed to retrieve contract state; {}', contract_id)

        return cls(contract_id, raw_state = raw_state)

    # --------------------------------------------------
    @classmethod
    def create_new_state(cls, contract_id) :
        return cls(contract_id)

    # --------------------------------------------------
    def __init__(self, contract_id, raw_state = '') :
        self.contract_id = contract_id
        self.update_state(raw_state)

    # --------------------------------------------------
    def decode_state(self) :
        """decode the raw root block and parse the JSON
        """

        if self.raw_state is None :
            return {}

        logger.debug('contract state: %s', self.raw_state)
        state = self.raw_state

        # backward compatibility with json parser
        try :
            state = state.decode('utf8')
        except AttributeError :
            pass

        state = state.rstrip('\0')
        return json.loads(state)

    # --------------------------------------------------
    def update_state(self, raw_state) :
        """update state information from the root block

        :param raw_state string: root block of contract state, json string
        """
        self.raw_state = raw_state
        self.component_block_ids = []

        if self.raw_state :
            json_main_state_block = self.decode_state()
            self.component_block_ids = json_main_state_block['BlockIds']

    # --------------------------------------------------
    def compute_ids_of_newblocks(self, old_block_ids):
        """ Compute the blocks in the change set : Used for replication. The change set includes the root block if there is any change.
        """
        self.changed_block_ids = []
        for block_id in self.component_block_ids:
            if block_id not in old_block_ids :
                self.changed_block_ids.append(block_id)

        # add state hash (not sure if this is part of component block_ids, if so we can skip the following)
        if len(self.changed_block_ids) > 0: # if there is any change, make sure that state hash is part of chaged_block_ids
            state_hash = self.get_state_hash(encoding='b64')
            if state_hash not in self.changed_block_ids:
                self.changed_block_ids.append(state_hash)

    #------------------------------------------------------
    def get_state_hash(self, encoding='raw') :
        """
        gets the hash of the contract state if it is non-empty
        returns None if no contract state exists
        """
        if self.raw_state:
            return ContractState.compute_hash(self.raw_state, encoding)
        return None

    # --------------------------------------------------
    def serialize_for_invocation(self) :
        """
        serializes the elements needed by the contract enclave to invoke the contract
        does not include the contract state itself
        """
        result = dict()
        result['ContractID'] = self.contract_id
        if self.raw_state :
            result['StateHash'] = ContractState.compute_hash(self.raw_state, encoding='b64')

        return result

    # --------------------------------------------------
    def push_state_to_eservice(self, eservice, data_dir = None) :
        """
        push the blocks associated with the state to the eservice

        :param eservice EnclaveServiceClient object:
        """

        if not self.raw_state :
            return

        block_ids = [ self.get_state_hash(encoding='b64') ]
        block_ids.extend(self.component_block_ids)

        pushed_blocks = ContractState.__push_blocks_to_eservice__(eservice, self.contract_id, block_ids, data_dir)

        logger.info("Pushed %d new blocks before contract update", pushed_blocks)

        stat_logger.debug('state length is %d, pushed %d new blocks', len(self.component_block_ids), pushed_blocks)

    # --------------------------------------------------
    def pull_state_from_eservice(self, eservice, data_dir = None) :
        """
        push the blocks associated with the state to the eservice

        :param eservice EnclaveServiceClient object:
        """

        if not self.raw_state :
            return

        # raw state already contains the data for the root block, just write it out
        ContractState.__cache_data_block__(self.contract_id, self.raw_state, data_dir)

        # and then make sure we have everything else we need for the state
        pulled_blocks = ContractState.__pull_blocks_from_eservice__(
            eservice, self.contract_id, self.component_block_ids, data_dir)

        stat_logger.debug('state length is %d, pulled %d new blocks', len(self.component_block_ids), pulled_blocks)

    # --------------------------------------------------
    def save_to_cache(self, data_dir = None) :
        ContractState.__cache_data_block__(self.contract_id, self.raw_state, data_dir)

    #---------------------------------------------------
