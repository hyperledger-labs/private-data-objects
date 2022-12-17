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
from pdo.submitter.create import create_submitter
import pdo.common.block_store_manager as pblocks
from pdo.service_client.storage import StorageServiceClient

import logging
logger = logging.getLogger(__name__)
stat_logger = logger.getChild('stats')

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ContractState(object) :
    # --------------------------------------------------
    @staticmethod
    def compute_state_hash(raw_state, encoding = 'raw') :
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
    def get_current_state_hash(ledger_config, contract_id) :
        """Retrieve the current state hash for the contract

        :param ledger_config dictionary: ledger configuration that must contain 'LedgerURL'
        :param contract_id str: contract identifier
        """
        registry_helper = create_submitter(ledger_config)

        try :
            # what is returned when the contract has been created but
            # state has not been initialized? need to detect this and
            # return some kind of "not found" exception
            state_info = registry_helper.get_current_state_hash(contract_id)
            if state_info['is_active']:
                return state_info['state_hash']
            else:
                raise Exception("Contract is no longer active")

        except Exception as e :
            logger.info('error getting state hash; %s', str(e))
            raise Exception('failed to retrieve contract state hash; {}'.format(contract_id))

    # --------------------------------------------------
    @classmethod
    def read_from_cache(cls, contract_id, state_hash) :
        """
        read a block from the local cache and create contract state for it

        :param contract_id str: contract identifier, base64 encoded
        :param state_hash str: b64 encoded string
        """
        raw_data = pblocks.local_block_manager().get_block(state_hash)
        if raw_data is None :
            logger.debug('state hash not found in the cache, {0}'.format(state_hash))
            return None

        return cls(contract_id, raw_data)

    # --------------------------------------------------
    @classmethod
    def import_from_persistent_storage(cls, contract_id, state_hash, persistent_replica) :
        """
        import contract state from a persistent storage service; primarily used to load
        a contract for the first time or to catch up on uncached state changes

        :param contract_id str: contract identifier, base64 encoded
        :param state_hash str: b64 encoded string
        :param persistent_replica : url for the persistent storage service
        """

        storage_service_client = StorageServiceClient(persistent_replica)
        block_manager = pblocks.local_block_manager()
        pulled_blocks = pblocks.sync_block_store(storage_service_client, block_manager, state_hash)
        logger.debug("imported %d new blocks from persistent storage service", pulled_blocks)

        return cls.read_from_cache(contract_id, state_hash)

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
        if self.raw_state is None :
            return None

        return pblocks.decode_root_block(self.raw_state)

    # --------------------------------------------------
    def update_state(self, raw_state) :
        """update state information from the root block

        :param raw_state string: root block of contract state, json string
        """
        self.raw_state = raw_state
        self.component_block_ids = []

        if self.raw_state :
            json_main_state_block = pblocks.decode_root_block(self.raw_state)
            self.component_block_ids = json_main_state_block['BlockIds']

    # --------------------------------------------------
    def compute_new_block_ids(self, old_block_ids):
        """ Compute the blocks in the change set
        Used for replication. The change set includes the root block
        if there is any change.
        """

        self.changed_block_ids = []
        for block_id in self.component_block_ids:
            if block_id not in old_block_ids :
                self.changed_block_ids.append(block_id)

        # add state hash (not sure if this is part of component block_ids, if so we can skip the following)
        # if there is any change, make sure that state hash is part of changed_block_ids
        if len(self.changed_block_ids) > 0 :
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
            return ContractState.compute_state_hash(self.raw_state, encoding)

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
            result['StateHash'] = ContractState.compute_state_hash(self.raw_state, encoding='b64')

        return result

    # --------------------------------------------------
    def push_state_to_eservice(self, eservice, data_dir = None) :
        """
        push the blocks associated with the state to the eservice

        :param eservice EnclaveServiceClient object:
        """

        if not self.raw_state :
            return

        block_manager = pblocks.local_block_manager()
        root_block_id = self.get_state_hash(encoding='b64')
        pushed_blocks = pblocks.sync_block_store(block_manager, eservice, root_block_id, self.raw_state)
        logger.debug("Pushed %d new blocks before contract update", pushed_blocks)

        stat_logger.debug('state length is %d, pushed %d new blocks', len(self.component_block_ids), pushed_blocks)

    # --------------------------------------------------
    def pull_state_from_eservice(self, eservice, data_dir = None) :
        """
        push the blocks associated with the state to the eservice

        :param eservice EnclaveServiceClient object:
        """

        if not self.raw_state :
            return

        block_manager = pblocks.local_block_manager()
        root_block_id = self.get_state_hash(encoding='b64')
        pulled_blocks = pblocks.sync_block_store(eservice, block_manager, root_block_id, self.raw_state)
        logger.debug("Pulled %d new blocks before contract update", pulled_blocks)

        stat_logger.debug('state length is %d, pulled %d new blocks', len(self.component_block_ids), pulled_blocks)
