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
import argparse
import logging
import random

logger = logging.getLogger(__name__)

import pdo.common.crypto as pcrypto

from pdo.client.controller.commands.eservice import get_eservice, get_eservice_list
from pdo.client.controller.commands.pservice import get_pservice_list

from pdo.common.keys import ServiceKeys
from pdo.contract import ContractCode
from pdo.contract import ContractState
from pdo.contract import Contract
from pdo.contract import register_contract
from pdo.contract import add_enclave_to_contract

__all__ = ['command_create']

## -----------------------------------------------------------------
def __add_enclave_secrets__(ledger_config, contract_id, client_keys, enclaveclients, provclients) :
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
def __create_contract__(ledger_config, client_keys, preferred_eservice_client, eservice_clients, contract) :
    """Create the initial contract state
    """

    logger.debug('Requesting that the enclave initialize the contract...')
    initialize_request = contract.create_initialize_request(client_keys, preferred_eservice_client)
    initialize_response = initialize_request.evaluate()
    if not initialize_response.status :
        raise Exception("failed to initialize the contract; %s", initialize_response.result)

    contract.set_state(initialize_response.raw_state)

    logger.debug('Contract state created successfully')

    # submit the commit task: (a commit task replicates change-set and submits the corresponding transaction)
    try:
        initialize_response.commit_asynchronously(ledger_config)
    except Exception as e:
        raise Exception('failed to submit commit: %s', str(e))

    # wait for the commit to finish
    try:
        txn_id = initialize_response.wait_for_commit()
        if txn_id is None:
            raise Exception("Did not receive txn id for the initial commit")
    except Exception as e:
        raise Exception("Error while waiting for commit: %s", str(e))

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def create_contract(state, save_file, contract_source, **kwargs) :
    """Expose the contract creation logic to other client applications

    @param save_file: file name for the local contract information
    @param contract_source : path to the contract source file
    @param contract_class : optional parameter to specific class in the contract source
    @param eservice_group : name of the eservice group to provision the contract
    @param pservice_group : name of the pservice group to provision the contract
    @param interpreter : name of the interpreter that is expected from the eservices
    @param state_replicas : number of mandatory copies of state
    @param state_duration : minimum duration replicas must be available
    @param extra_data : opaque data that can be store in the contract file
    """

    contract_class = kwargs.get('contract_class') or os.path.basename(contract_source)
    eservice_group = kwargs.get('eservice_group') or 'default'
    pservice_group = kwargs.get('pservice_group') or 'default'
    interpreter = kwargs.get('interpreter') or state.get(['Contract', 'Interpreter'])
    state_replicas = kwargs.get('state_replicas') or state.get(['Replication', 'NumProvableReplicas'], 2)
    state_duration = kwargs.get('state_duration') or state.get(['Replication', 'Duration'], 120)
    extra_data = kwargs.get('extra_data')

    # ---------- load the invoker's keys ----------
    try :
        keyfile = state.private_key_file
        keypath = state.get(['Key', 'SearchPath'])
        client_keys = ServiceKeys.read_from_file(keyfile, keypath)
    except Exception as e :
        raise Exception('unable to load client keys; {0}'.format(str(e)))

    # ---------- read the contract source code ----------
    try :
        source_path = state.get(['Contract', 'SourceSearchPath'])
        contract_code = ContractCode.create_from_file(
            contract_class, contract_source, source_path, interpreter=interpreter)
    except Exception as e :
        raise Exception('unable to load contract source; {0}'.format(str(e)))

    logger.debug('Loaded contract code for %s', contract_class)

    # ---------- set up the enclave clients ----------
    eservice_clients = get_eservice_list(state, eservice_group)
    if len(eservice_clients) == 0 :
        raise Exception('unable to locate enclave services in the group %s', eservice_group)

    preferred_eservice_client = get_eservice(state, eservice_group=eservice_group)
    if preferred_eservice_client.interpreter != interpreter :
        raise Exception('enclave interpreter does not match requested contract interpreter %s', interpreter)

    # ---------- set up the provisioning service clients ----------
    pservice_clients = get_pservice_list(state, pservice_group)
    if len(pservice_clients) == 0 :
        raise Exception('unable to locate provisioning services in the group %s', pservice_group)

    # ---------- register contract ----------
    data_directory = state.get(['Contract', 'DataDirectory'])
    ledger_config = state.get(['Ledger'])

    try :
        extra_params = {
            'num_provable_replicas' : state_replicas,
            'availability_duration' : state_duration,
        }

        if extra_data :
            extra_params['extra_data'] = extra_data

        provisioning_service_keys = [pc.identity for pc in pservice_clients]
        contract_id = register_contract(
            ledger_config, client_keys, contract_code, provisioning_service_keys)

        logger.debug('Registered contract with class %s and id %s', contract_class, contract_id)
        contract_state = ContractState.create_new_state(contract_id)
        contract = Contract(contract_code, contract_state, contract_id, client_keys.identity, **extra_params)

        # must fix this later
        contract.extra_data['preferred-enclave'] = preferred_eservice_client.enclave_id

        contract_file = "{0}_{1}.pdo".format(contract_class, contract.short_id)
        if save_file :
            contract_file = save_file

        contract.save_to_file(contract_file, data_dir=data_directory)

    except Exception as e :
        raise Exception('failed to register the contract; {0}'.format(str(e)))

    # provision the encryption keys to all of the enclaves
    try :
        encrypted_state_encryption_keys = __add_enclave_secrets__(
            ledger_config, contract.contract_id, client_keys, eservice_clients, pservice_clients)

        for enclave_id in encrypted_state_encryption_keys :
            encrypted_key = encrypted_state_encryption_keys[enclave_id]
            contract.set_state_encryption_key(enclave_id, encrypted_key)

        contract.save_to_file(contract_file, data_dir=data_directory)
    except Exception as e :
        raise Exception('failed to provisioning the enclaves; {0}'.format(str(e)))

    # create the initial contract state
    try :
        __create_contract__(ledger_config, client_keys, preferred_eservice_client, eservice_clients, contract)

        contract.save_to_file(contract_file, data_dir=data_directory)
    except Exception as e :
        raise Exception('failed to create the initial contract state; {0}'.format(str(e)))

    return contract_file

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_create(state, bindings, pargs) :
    """controller command to create a contract
    """

    parser = argparse.ArgumentParser(prog='create')
    parser.add_argument('-c', '--contract-class', help='Name of the contract class', type=str)
    parser.add_argument('-e', '--eservice-group', help='Name of the enclave service group to use', type=str)
    parser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str)
    parser.add_argument('-i', '--interpreter', help='Interpreter used to evaluate the contract', type=str)
    parser.add_argument('-p', '--pservice-group', help='Name of the provisioning service group to use', type=str)
    parser.add_argument('-s', '--contract-source', help='File that contains contract source code', required=True, type=str)

    parser.add_argument('--symbol', help='binding symbol for result', type=str)
    parser.add_argument('--state-replicas', help='Number of authoritative replicas of the state', type=int)
    parser.add_argument('--state-duration', help='Duration required for state replicas', type=int)
    parser.add_argument('--extra-data', help='Simple string that can save extra data with the contract file', type=str)

    options = parser.parse_args(pargs)

    contract_id = create_contract(state, **vars(options))
    if contract_id and options.symbol :
        bindings.bind(options.symbol, contract_id)
