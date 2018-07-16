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
import random

logger = logging.getLogger(__name__)

import pdo.common.crypto as pcrypto

from pdo.common.keys import ServiceKeys
from pdo.contract import ContractCode
from pdo.contract import ContractState
from pdo.contract import Contract
from pdo.contract import register_contract
from pdo.contract import add_enclave_to_contract
from pdo.service_client.enclave import EnclaveServiceClient
from pdo.service_client.provisioning import ProvisioningServiceClient

__all__ = ['command_create']

## -----------------------------------------------------------------
def __add_enclave_secrets(ledger_config, contract_id, client_keys, enclaveclients, provclients) :
    """Create and provision the encrypted secrets for each of the
    enclaves that will be provisioned for this contract.
    """

    secrets = {}
    encrypted_state_encryption_keys = {}
    for enclaveclient in enclaveclients:
        psecrets = []
        for provclient in provclients:
            # Get a pspk:esecret pair from the provisioning service for each enclave
            sig_payload = pcrypto.string_to_byte_array(enclaveclient.enclave_id + contract_id)
            secretinfo = provclient.get_secret(enclaveclient.enclave_id,
                                               contract_id,
                                               client_keys.verifying_key,
                                               client_keys.sign(sig_payload))
            logger.debug("pservice secretinfo: %s", secretinfo)

            # Add this pspk:esecret pair to the list
            psecrets.append(secretinfo)

        # Print all of the secret pairs generated for this particular enclave
        logger.debug('psecrets for enclave %s : %s', enclaveclient.enclave_id, psecrets)

        # Verify those secrets with the enclave
        esresponse = enclaveclient.verify_secrets(contract_id, client_keys.verifying_key, psecrets)
        logger.debug("verify_secrets response: %s", esresponse)

        # Store the ESEK mapping in a dictionary key'd by the enclave's public key (ID)
        encrypted_state_encryption_keys[enclaveclient.enclave_id] = esresponse['encrypted_state_encryption_key']

        # Add this spefiic enclave to the contract
        add_enclave_to_contract(ledger_config,
                                client_keys,
                                contract_id,
                                enclaveclient.enclave_id,
                                psecrets,
                                esresponse['encrypted_state_encryption_key'],
                                esresponse['signature'])

    return encrypted_state_encryption_keys

## -----------------------------------------------------------------
def __create_contract(ledger_config, client_keys, enclaveclients, contract) :
    """Create the initial contract state
    """

    # Choose one enclave at random to use to create the contract
    enclaveclient = random.choice(enclaveclients)

    logger.info('Requesting that the enclave initialize the contract...')
    initialize_request = contract.create_initialize_request(client_keys, enclaveclient)
    initialize_response = initialize_request.evaluate()
    if not initialize_response.status :
        raise Exception("failed to initialize the contract; %s", initialize_response.result)

    contract.set_state(initialize_response.encrypted_state)

    logger.info('Contract state created successfully')

    logger.info('Saving the initial contract state in the ledger...')

    cclinit_result = initialize_response.submit_initialize_transaction(ledger_config, wait=30.0)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_create(state, bindings, pargs) :
    """controller command to create a contract
    """

    parser = argparse.ArgumentParser(prog='create')
    parser.add_argument('-c', '--contract-class', help='Name of the contract class', required = True, type=str)
    parser.add_argument('-s', '--contract-source', help='File that contains contract source code', required=True, type=str)
    parser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str)
    parser.add_argument('--symbol', help='binding symbol for result', type=str)
    options = parser.parse_args(pargs)

    contract_class = options.contract_class
    contract_source = options.contract_source

    contract_file = "{0}.pdo".format(contract_class)
    if options.save_file :
        contract_file = options.save_file

    # ---------- load the invoker's keys ----------
    try :
        keyfile = state.get(['Key', 'FileName'])
        keypath = state.get(['Key', 'SearchPath'])
        client_keys = ServiceKeys.read_from_file(keyfile, keypath)
    except Exception as e :
        raise Exception('unable to load client keys; {0}'.format(str(e)))

    # ---------- read the contract source code ----------
    try :
        source_path = state.get(['Contract', 'SourceSearchPath'])
        contract_code = ContractCode.create_from_scheme_file(contract_class, contract_source, source_path)
    except Exception as e :
        raise Exception('unable to load contract source; {0}'.format(str(e)))

    logger.info('Loaded contract code for %s', contract_class)

    # ---------- set up the enclave clients ----------
    try :
        eservice_urls = state.get(['Service', 'EnclaveServiceURLs'], [])
        if len(eservice_urls) == 0 :
            raise Exception('no enclave services specified')

        enclaveclients = []
        for url in eservice_urls :
            enclaveclients.append(EnclaveServiceClient(url))
    except Exception as e :
        raise Exception('unable to contact enclave services; {0}'.format(str(e)))

    # ---------- set up the provisioning service clients ----------
    # This is a dictionary of provisioning service public key : client pairs
    try :
        pservice_urls = state.get(['Service', 'ProvisioningServiceURLs'])
        if len(pservice_urls) == 0 :
            raise Exception('no provisioning services specified')

        provclients = []
        for url in pservice_urls :
            provclients.append(ProvisioningServiceClient(url))
    except Exception as e :
        raise Exception('unable to contact provisioning services; {0}'.format(str(e)))

    # ---------- register contract ----------
    data_directory = state.get(['Contract', 'DataDirectory'])
    ledger_config = state.get(['Sawtooth'])

    try :
        provisioning_service_keys = [pc.identity for pc in provclients]
        contract_id = register_contract(
            ledger_config, client_keys, contract_code, provisioning_service_keys)

        logger.info('Registered contract with class %s and id %s', contract_class, contract_id)
        contract_state = ContractState.create_new_state(contract_id)
        contract = Contract(contract_code, contract_state, contract_id, client_keys.identity)
        contract.save_to_file(contract_file, data_dir=data_directory)
    except Exception as e :
        raise Exception('failed to register the contract; {0}'.format(str(e)))

    # provision the encryption keys to all of the enclaves
    try :
        encrypted_state_encryption_keys = __add_enclave_secrets(
            ledger_config, contract.contract_id, client_keys, enclaveclients, provclients)

        for enclave_id in encrypted_state_encryption_keys :
            encrypted_key = encrypted_state_encryption_keys[enclave_id]
            contract.set_state_encryption_key(enclave_id, encrypted_key)

        contract.save_to_file(contract_file, data_dir=data_directory)
    except Exception as e :
        raise Exception('failed to provisioning the enclaves; {0}'.format(str(e)))

    # create the initial contract state
    try :
        __create_contract(ledger_config, client_keys, enclaveclients, contract)

        contract.contract_state.save_to_cache(data_dir = data_directory)
        contract.save_to_file(contract_file, data_dir=data_directory)
    except Exception as e :
        raise Exception('failed to create the initial contract state; {0}'.format(str(e)))

    if contract_id and options.symbol :
        bindings.bind(options.symbol, contract_id)
