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
import logging
logger = logging.getLogger(__name__)

from pdo.common.keys import ServiceKeys
from pdo.service_client.enclave import EnclaveServiceClient

from pdo.client.controller.commands.contract import get_contract
from pdo.client.controller.commands.eservice import get_enclave_service

__all__ = ['command_send']

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def send_to_contract(state, save_file, enclave, message, quiet=False, wait=False, commit=True) :

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
    try :
        enclave_client = get_enclave_service(state, enclave)
    except Exception as e :
        raise Exception('unable to connect to enclave service; {0}'.format(str(e)))

    try :
        # this is just a sanity check to make sure the selected enclave
        # has actually been provisioned
        contract.get_state_encryption_key(enclave_client.enclave_id)
    except KeyError as ke :
        logger.error('selected enclave is not provisioned')
        sys.exit(-1)

    # ---------- send the message to the enclave service ----------
    try :
        update_request = contract.create_update_request(client_keys, enclave_client, message)
        update_response = update_request.evaluate()
        if update_response.status :
            if not quiet : print(update_response.result)
        else :
            print('ERROR: {}'.format(update_response.result))
            return None
    except Exception as e:
        raise Exception('enclave failed to evaluation expression; {0}'.format(str(e)))

    data_directory = state.get(['Contract', 'DataDirectory'])
    ledger_config = state.get(['Sawtooth'])

    if update_response.state_changed and commit :
        try :
            logger.debug("send update to the ledger")
            extraparams = {}
            if wait :
                extraparams['wait'] = 30
            txnid = update_response.submit_update_transaction(ledger_config, **extraparams)
        except Exception as e :
            raise Exception('failed to save the new state; {0}'.format(str(e)))

        try :
            contract.set_state(update_response.encrypted_state)
            contract.contract_state.save_to_cache(data_dir = data_directory)
        except Exception as e :
            logger.exception('BAD RESPONSE: %s, %s', update_response.status, update_response.result)

    return update_response.result

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_send(state, bindings, pargs) :
    """controller command to send a message to a contract
    """

    parser = argparse.ArgumentParser(prog='read')
    parser.add_argument('-e', '--enclave', help='URL of the enclave service to use', type=str)
    parser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str)
    parser.add_argument('-s', '--symbol', help='Save the result in a symbol for later use', type=str)
    parser.add_argument('--wait', help='Wait for the transaction to commit', action = 'store_true')
    parser.add_argument('message', help='Message to be sent to the contract', type=str)

    options = parser.parse_args(pargs)
    message = options.message
    waitflag = options.wait

    result = send_to_contract(state, options.save_file, options.enclave, options.message)
    if options.symbol :
        bindings.bind(options.symbol, result)
