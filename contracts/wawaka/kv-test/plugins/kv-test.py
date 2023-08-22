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

import argparse
import json
import logging

logger = logging.getLogger(__name__)

import pdo.client.builder.shell as pshell
import pdo.client.builder.contract as pcontract

from pdo.client.commands.contract import send_to_contract
from pdo.client.commands.eservice import get_eservice_from_contract
from pdo.contract import invocation_request
from pdo.common.key_value import KeyValueStore

__all__ = [
    'contract_op_get',
    'contract_op_set',
    'do_kv_test',
    'load_commands',
]

## -----------------------------------------------------------------
class contract_op_get(pcontract.contract_op_base) :
    name = "get"
    help = "Get a value from the test contract using a kv store"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('-k', '--key', dest='transfer_key', help='transfer key', type=str, default='_transfer_')

    @classmethod
    def invoke(cls, state, session_params, transfer_key, **kwargs) :
        kv = KeyValueStore()
        with kv :
            kv.set(transfer_key, '')

        # push the blocks to the eservice so the server can open the store
        eservice_client = get_eservice_from_contract(state, session_params.save_file, session_params.eservice_url)
        kv.sync_to_block_store(eservice_client)

        params = {}
        params['encryption_key'] = kv.encryption_key
        params['state_hash'] = kv.hash_identity
        params['transfer_key'] = transfer_key
        message = invocation_request('kv_get', **params)
        result = send_to_contract(state, message, **session_params)
        result = json.loads(result)       # get the hash for the root of the blockstore

        # sync the server blocks get to the local block manager
        _ = kv.sync_from_block_store(result, eservice_client)

        with kv :
            value = kv.get(transfer_key)

        logger.debug("value: %s", value)
        return value

## -----------------------------------------------------------------
class contract_op_set(pcontract.contract_op_base) :
    name = "set"
    help = "Set a value for the test contract using a kv store"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('-k', '--key', dest='transfer_key', help='transfer key', type=str, default='_transfer_')
        subparser.add_argument('-v', '--value', help='value to send', type=str, required=True)

    @classmethod
    def invoke(cls, state, session_params, transfer_key, value, **kwargs) :
        # this method changes the contract & we need to commit the changes
        # to use them later
        session_params = session_params.clone(commit=True)

        kv = KeyValueStore()
        with kv :
            v = kv.set(transfer_key, value)

        # push the blocks to the eservice so the server can open the store
        eservice_client = get_eservice_from_contract(state, session_params.save_file, session_params.eservice_url)
        if not eservice_client :
            raise Exception('unknown eservice {}'.format(session_params.eservice_url))

        _ = kv.sync_to_block_store(eservice_client)

        params = {}
        params['encryption_key'] = kv.encryption_key
        params['state_hash'] = kv.hash_identity
        params['transfer_key'] = transfer_key
        message = invocation_request('kv_set', **params)
        result = send_to_contract(state, message, **session_params)

        return result

## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__subcommands__ = [
    contract_op_get,
    contract_op_set,
]
do_kv_test = pcontract.create_shell_command('kv_test_contract', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'kv_test_contract', do_kv_test)
