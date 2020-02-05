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
import logging

logger = logging.getLogger(__name__)

from pdo.contract import ContractState
from pdo.contract import Contract

__all__ = [
    'command_contract',
    'get_contract',
    'load_contract',
    'refresh_contract',
    'save_contract'
    ]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_contract(state, bindings, pargs) :
    """controller command to manage contracts
    """

    parser = argparse.ArgumentParser(prog='contract')

    subparsers = parser.add_subparsers(dest='command')
    load_parser = subparsers.add_parser('load')
    load_parser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str, required=True)
    load_parser.add_argument('-r', '--refresh', help='Refresh state from ledger', action='store_true')

    refresh_parser = subparsers.add_parser('refresh')
    refresh_parser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str)

    options = parser.parse_args(pargs)

    if options.command == 'load' :
        contract = load_contract(state, options.save_file)

        if options.refresh :
            refresh_contract(state, contract)

        save_contract(state, options.save_file, contract)

    elif options.command == 'refresh' :
        contract = get_contract(state, options.save_file)
        refresh_contract(state, contract)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def refresh_contract(state, contract) :
    try :
        data_directory = state.get(['Contract', 'DataDirectory'])
        ledger_config = state.get(['Ledger'])

        contract_state = ContractState.get_from_ledger(ledger_config, contract.contract_id)
        contract_state.save_to_cache(data_dir=data_directory)
        contract.set_state(contract_state.raw_state)
    except Exception as e :
        raise Exception('unable to refresh the state from the ledger; {0}'.format(str(e)))

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def save_contract(state, contract_file, contract) :
    state.set(['Contract', 'SaveFile'], contract_file)
    state.set(['Contract', 'Name'], contract.contract_code.name)
    state.set(['Contract', 'Contract'], contract)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def load_contract(state, contract_file) :
    try :
        data_directory = state.get(['Contract', 'DataDirectory'])
        ledger_config = state.get(['Ledger'])

        return Contract.read_from_file(ledger_config, contract_file, data_dir=data_directory)
    except Exception as e :
        raise Exception('unable to load the contract; {0}'.format(str(e)))

## -----------------------------------------------------------------
## -----------------------------------------------------------------
__contract_cache__ = {}

def get_contract(state, save_file=None) :
    """ Get contract object using the save_file. If there is no save_file, try loading contract using config."""

    global __contract_cache__

    if save_file is None :
        current_contract = state.get(['Contract', 'Contract'], None)
        if current_contract is not None :
            return current_contract

        save_file = state.get(['Contract', 'SaveFile'], None)
        if save_file is None :
            raise Exception('no contract specified')

    if save_file not in __contract_cache__ :
        __contract_cache__[save_file] = load_contract(state, save_file)

    return __contract_cache__[save_file]
