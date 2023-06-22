# Copyright 2023 Intel Corporation
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
import copy
import json
import logging

logger = logging.getLogger(__name__)

import pdo.client.builder as pbuilder
import pdo.client.builder.shell as pshell
import pdo.client.builder.script as pscript
from pdo.submitter.create import create_submitter

__all__ = [
    'create_submitter_from_state',
    'ledger_key',
    'enclave_info',
    'contract_info',
    'current_state',
    'state_info',
    'do_ledger',
    'load_commands',
]

## -----------------------------------------------------------------
def create_submitter_from_state(state, url=None) :
    ledger_config = state.get(['Ledger'])
    if url :
        ledger_config = copy.deepcopy(ledger_config)
        ledger_config['LedgerURL'] = url
    return create_submitter(ledger_config)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_ledger_key(pscript.script_command_base) :
    """Script command to retrieve the ledger's verifying key
    """
    name = "ledger-key"
    help = "Retrieve the verifying key from the ledger"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--url', help='URL for the ledger', type=str)

    @classmethod
    def invoke(cls, state, bindings, **kwargs) :
        submitter = create_submitter_from_state(state, kwargs.get('url'))
        return submitter.get_ledger_info()

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_enclave_info(pscript.script_command_base) :
    """
    """
    name = "enclave-info"
    help = ""

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--url', help='URL for the ledger', type=str)
        subparser.add_argument('-i', '--enclave-id', help='enclave identifier', type=str, required=True)
        subparser.add_argument('-p', '--path', help='path to retrieve within the expression', nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, enclave_id, **kwargs) :
        submitter = create_submitter_from_state(state, kwargs.get('url'))
        result = submitter.get_enclave_info(enclave_id)
        return pbuilder.process_structured_invocation_result(result, kwargs.get('path'))

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_contract_info(pscript.script_command_base) :
    """
    """
    name = "contract-info"
    help = ""

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--url', help='URL for the ledger', type=str)
        subparser.add_argument('-i', '--contract-id', help='contract identifier', type=str, required=True)
        subparser.add_argument('-p', '--path', help='path to retrieve within the expression', nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, contract_id, **kwargs) :
        submitter = create_submitter_from_state(state, kwargs.get('url'))
        result = submitter.get_contract_info(contract_id)
        return pbuilder.process_structured_invocation_result(result, kwargs.get('path'))

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_current_state(pscript.script_command_base) :
    """
    """
    name = "current-state"
    help = ""

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--url', help='URL for the ledger', type=str)
        subparser.add_argument('-i', '--contract-id', help='contract identifier', type=str, required=True)
        subparser.add_argument('-p', '--path', help='path to retrieve within the expression', nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, contract_id, **kwargs) :
        submitter = create_submitter_from_state(state, kwargs.get('url'))
        result = submitter.get_current_state_hash(contract_id)
        return pbuilder.process_structured_invocation_result(result, kwargs.get('path'))

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_state_info(pscript.script_command_base) :
    """
    """
    name = "state-info"
    help = ""

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--url', help='URL for the ledger', type=str)
        subparser.add_argument('-a', '--state-hash', help='state hash', type=str, required=True)
        subparser.add_argument('-i', '--contract-id', help='contract identifier', type=str, required=True)
        subparser.add_argument('-p', '--path', help='path to retrieve within the expression', nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, contract_id, state_hash, **kwargs) :
        submitter = create_submitter_from_state(state, kwargs.get('url'))
        result = submitter.get_state_details(contract_id, state_hash)
        return pbuilder.process_structured_invocation_result(result, kwargs.get('path'))

ledger_key = script_command_ledger_key.invoke
enclave_info = script_command_enclave_info.invoke
contract_info = script_command_contract_info.invoke
current_state = script_command_current_state.invoke
state_info = script_command_state_info.invoke

## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__subcommands__ = [
    script_command_ledger_key,
    script_command_enclave_info,
    script_command_contract_info,
    script_command_current_state,
    script_command_state_info,
]
do_ledger = pscript.create_shell_command('ledger', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'ledger', do_ledger)
