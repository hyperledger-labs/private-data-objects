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
import random
import sys

import logging
logger = logging.getLogger(__name__)

from pdo.common.keys import ServiceKeys
from pdo.service_client.enclave import EnclaveServiceClient

from pdo.client.controller.commands.contract import get_contract
from pdo.client.controller.commands.eservice import get_eservice
import pdo.service_client.service_data.eservice as eservice_db

__all__ = ['command_send', 'send_to_contract']

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def send_to_contract(state, save_file, message, eservice_url=None, quiet=False, wait=False, commit=True) :

    # ---------- load the invoker's keys ----------
    try :
        keyfile = state.get(['Key', 'FileName'])
        keypath = state.get(['Key', 'SearchPath'])
        client_keys = ServiceKeys.read_from_file(keyfile, keypath)
    except Exception as e :
        raise Exception('unable to load client keys; {0}'.format(str(e)))

    # ---------- read the contract ----------
    try :
        contract = get_contract(state, save_file)
    except Exception as e :
        raise Exception('unable to load the contract')

    # ---------- set up the enclave service ----------
    if eservice_url is None :
        eservice_url = 'preferred'

    if eservice_url not in ['random', 'preferred'] :
        try :
            eservice_client = EnclaveServiceClient(eservice_url)
        except Exception as e :
            raise Exception('unable to connect to enclave service; {0}'.format(str(e)))

        if eservice_client.enclave_id not in contract.provisioned_enclaves :
            raise Exception('requested enclave not provisioned for the contract; %s', eservice_url)
    else :
        if eservice_url == 'preferred' :
            enclave_id = contract.extra_data.get('preferred-enclave', random.choice(contract.provisioned_enclaves))
        else :
            enclave_id = random.choice(contract.provisioned_enclaves)

        eservice_info = eservice_db.get_info_by_id(enclave_id)
        if eservice_info is None :
            raise Exception('attempt to use an unknown enclave; %s', enclave_id)

        try :
            eservice_client = EnclaveServiceClient(eservice_info['url'])
        except Exception as e :
            raise Exception('unable to connect to enclave service; {0}'.format(str(e)))

    # ---------- send the message to the enclave service ----------
    try :
        update_request = contract.create_update_request(client_keys, message, eservice_client)
        update_response = update_request.evaluate()
    except Exception as e:
        raise Exception('enclave failed to evaluate expression; {0}'.format(str(e)))

    if not update_response.status :
        # not sure if this should throw an exception which would
        # terminate the script or if it should just return an
        # empty string that can be tested for later
        # if not quiet :
        #     print("FAILED: {0}".format(update_response.result))
        # return ''
        raise ValueError(update_response.result)

    if not quiet :
        print(update_response.result)

    data_directory = state.get(['Contract', 'DataDirectory'])
    ledger_config = state.get(['Sawtooth'])

    if update_response.state_changed and commit :

        contract.set_state(update_response.raw_state)

        # asynchronously submit the commit task: (a commit task replicates change-set and submits the corresponding transaction)
        try:
            update_response.commit_asynchronously(ledger_config)
        except Exception as e:
            raise Exception('failed to submit commit: %s', str(e))

        # wait for the commit to finish.
        # TDB: 1. make wait_for_commit a separate shell command. 2. Add a provision to specify commit dependencies as input to send command.
        # 3. Return commit_id after send command back to shell so as to use as input commit_dependency in a future send command
        try:
            txn_id = update_response.wait_for_commit()
            if txn_id is None:
                raise Exception("Did not receive txn id for the send operation")
        except Exception as e:
            raise Exception("Error while waiting for commit: %s", str(e))

        try :
            contract.contract_state.save_to_cache(data_dir = data_directory)
        except Exception as e :
            logger.exception('failed to save the new state in the cache')

    return update_response.result

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_send(state, bindings, pargs) :
    """controller command to send a message to a contract
    """

    parser = argparse.ArgumentParser(prog='send')
    parser.add_argument('-e', '--enclave', help='URL of the enclave service to use', type=str)
    parser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str)
    parser.add_argument('-s', '--symbol', help='Save the result in a symbol for later use', type=str)
    parser.add_argument('-q', '--quiet', help='Do not print the result', action='store_true')
    parser.add_argument('--wait', help='Wait for the transaction to commit', action = 'store_true')
    parser.add_argument('message', help='Message to be sent to the contract', type=str)

    options = parser.parse_args(pargs)
    message = options.message
    waitflag = options.wait

    result = send_to_contract(
        state,
        options.save_file,
        options.message,
        eservice_url=options.enclave,
        quiet=options.quiet,
        wait=options.wait)
    if options.symbol :
        bindings.bind(options.symbol, result)
