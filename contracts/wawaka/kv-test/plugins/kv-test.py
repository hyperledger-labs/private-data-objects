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

from pdo.service_client.service_data.service_data import ServiceDatabaseManager as service_data
from pdo.client.controller.commands.send import send_to_contract, get_contract

from pdo.client.controller.util import *
from pdo.contract import invocation_request
from pdo.common.key_value import KeyValueStore
import pdo.common.block_store_manager as pblocks

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def __get_eservice_client__(state, save_file, eservice_url) :

    try :
        contract = get_contract(state, save_file)
    except Exception as e :
        raise Exception('unable to load the contract')

    if eservice_url not in ['random', 'preferred'] :
        try :
            try :
                eservice_info = service_data.local_service_manager.get_by_url(eservice_url, 'eservice')
            except RuntimeError as e :
                # if it wasn't in the database, add the enclave service using the URL
                eservice_info = service_data.local_service_manager.store_by_url(eservice_url, 'eservice')

            eservice_client = eservice_info.client()
        except Exception as e :
            raise Exception('unable to connect to enclave service; {0}'.format(str(e)))

        if eservice_client.enclave_id not in contract.provisioned_enclaves :
            raise Exception('requested enclave not provisioned for the contract; %s', eservice_url)
    else :
        if eservice_url == 'preferred' :
            enclave_id = contract.extra_data.get('preferred-enclave', random.choice(contract.provisioned_enclaves))
        else :
            enclave_id = random.choice(contract.provisioned_enclaves)

        eservice_info = service_data.local_service_manager.get_by_identity(enclave_id, 'eservice')
        if eservice_info is None :
            raise Exception('attempt to use an unknown enclave; %s', enclave_id)

        try :
            eservice_client = eservice_info.client()
        except Exception as e :
            raise Exception('unable to connect to enclave service; {0}'.format(str(e)))

    return eservice_client


## -----------------------------------------------------------------
## -----------------------------------------------------------------
def __command_kv__(state, bindings, pargs) :
    """controller command to interact with an asset_type contract
    """

    parser = argparse.ArgumentParser(prog='attestation-test')
    parser.add_argument('-e', '--enclave', help='URL of the enclave service to use', type=str, default='preferred')
    parser.add_argument('-f', '--save_file', help='File where contract data is stored', type=str)
    parser.add_argument('-w', '--wait', help='Wait for the transaction to commit', action='store_true')

    subparsers = parser.add_subparsers(dest='command')

    subparser = subparsers.add_parser('get')
    subparser.add_argument('-k', '--key', help='transfer key', type=str, default='_transfer_')
    subparser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

    subparser = subparsers.add_parser('set')
    subparser.add_argument('-k', '--key', help='transfer key', type=str, default='_transfer_')
    subparser.add_argument('-v', '--value', help='value to send', type=str, required=True)

    options = parser.parse_args(pargs)

    extraparams={'wait' : options.wait}

    # -------------------------------------------------------
    if options.command == 'get' :

        kv = KeyValueStore()
        with kv :
            kv.set(options.key, "")

        # push the blocks to the eservice so the server can open the store
        eservice_client = __get_eservice_client__(state, options.save_file, options.enclave)
        kv.sync_to_block_store(eservice_client)

        params = {}
        params['encryption_key'] = kv.encryption_key
        params['state_hash'] = kv.hash_identity
        params['transfer_key'] = options.key
        message = invocation_request('kv_get', **params)
        result = send_to_contract(state, message, save_file=options.save_file, eservice_url=options.enclave, **extraparams)
        result = json.loads(result)

        # sync the server blocks get to the local block manager
        count = kv.sync_from_block_store(result, eservice_client)
        logger.debug("sync complete with %d blocks", count)

        with kv :
            value = kv.get(options.key)
            logger.debug("value: %s", value)

        if options.symbol :
            bindings.bind(options.symbol, value)

        return value

    # -------------------------------------------------------
    if options.command == 'set' :

        kv = KeyValueStore()
        with kv :
            kv.set(options.key, options.value)

        # push the blocks to the eservice so the server can open the store
        # local_block_store = pblocks.local_block_manager()
        eservice_client = __get_eservice_client__(state, options.save_file, options.enclave)
        kv.sync_to_block_store(eservice_client)

        params = {}
        params['encryption_key'] = kv.encryption_key
        params['state_hash'] = kv.hash_identity
        params['transfer_key'] = options.key
        message = invocation_request('kv_set', **params)
        send_to_contract(state, message, save_file=options.save_file, eservice_url=options.enclave, **extraparams)

        return

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def do_kv(self, args) :
    """
    attestation -- methods on the attestation contract
    """

    if self.deferred > 0 : return False

    try :
        pargs = self.__arg_parse__(args)
        __command_kv__(self.state, self.bindings, pargs)

    except SystemExit as se :
        return self.__arg_error__('kv', args, se.code)
    except Exception as e :
        return self.__error__('kv', args, str(e))

    return False

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    setattr(cmdclass, 'do_kv', do_kv)
