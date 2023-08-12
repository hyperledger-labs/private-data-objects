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
import logging
import os
import random
import pdo.client.builder.shell as pshell
import pdo.client.builder.script as pscript
import pdo.client.commands.sservice as sservice
import pdo.client.commands.pservice as pservice
import pdo.client.commands.eservice as eservice
from pdo.client.builder import invocation_parameter

import pdo.common.crypto as pcrypto
import pdo.contract as pcontract
from pdo.common.keys import ServiceKeys
from pdo.common.utility import valid_service_url
from pdo.submitter.create import create_submitter

logger = logging.getLogger(__name__)

__all__ = [
    'get_contract',
    'get_contract_from_context',
    'create_contract',
    'send_to_contract',
    'do_contract',
    'load_commands',
    ]

## -----------------------------------------------------------------
## get_contract
## -----------------------------------------------------------------
__contract_cache__ = {}

def get_contract(state, save_file) :
    """Get contract object using the save_file.
    """

    global __contract_cache__

    if save_file not in __contract_cache__ :
        try :
            data_directory = state.get(['Contract', 'DataDirectory'])
            ledger_config = state.get(['Ledger'])

            __contract_cache__[save_file] = pcontract.Contract.read_from_file(
                ledger_config, save_file, data_dir=data_directory)
        except Exception as e :
            raise Exception('unable to load the contract; {0}'.format(str(e)))

    return __contract_cache__[save_file]

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def get_contract_from_context(state, context) :
    save_file = context.get('save_file')
    if save_file is None :
        # to preserve the abstraction we need to handle the case
        # where an object may be invocable but not have a contract
        # associated with it; in that case, just return a special
        # constant
        if context.get('service_only') :
            return "**service_only**"
        else :
            return None

    # test to see if the save file exists & contains a contract; this
    # will also cache the contract object which we will probably be
    # using again later
    try :
        contract = get_contract(state, save_file)
        logger.debug('contract found in file {}'.format(save_file))
    except Exception as e :
        logger.info("contract save file specified in context, but load failed; {}".format(e))
        return None

    return save_file

## -----------------------------------------------------------------
## create_contract
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
        pcontract.add_enclave_to_contract(ledger_config,
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
def create_contract(state, source, **kwargs) :
    """Expose the contract creation logic to other client applications

    @param source : path to the contract source file
    @param save_file: file name for the local contract information
    @param contract_class : optional parameter to specific class in the contract source
    @param eservice_group : name of the eservice group to provision the contract
    @param pservice_group : name of the pservice group to provision the contract
    @param sservice_group : name of the sservice group to specify storage parameters
    @param interpreter : name of the interpreter that is expected from the eservices
    @param key_file : name of the file storing the keys to use for the transactions
    @param extra : opaque data that can be store in the contract file
    """

    save_file = kwargs.get('save_file')
    contract_class = kwargs.get('contract_class') or os.path.basename(source)
    eservice_group = kwargs.get('eservice_group') or 'default'
    pservice_group = kwargs.get('pservice_group') or 'default'
    sservice_group = kwargs.get('sservice_group') or 'default'
    interpreter = kwargs.get('interpreter') or state.get(['Contract', 'Interpreter'])
    keyfile = kwargs.get('key_file') or state.private_key_file
    extra_data = kwargs.get('extra') or dict()

    # ---------- pull out replication parameters ----------
    replica_count = sservice.get_replica_count(state, sservice_group)
    replica_duration = sservice.get_replica_duration(state, sservice_group)
    replicas = sservice.get_replica_list(state, sservice_group)
    if 'persistent_storage_service' not in extra_data :
        persistent_url = sservice.get_persistent_storage_service(state, sservice_group)
        if persistent_url :
            extra_data['persistent_storage_service'] = persistent_url

    # ---------- load the invoker's keys ----------
    try :
        keypath = state.get(['Key', 'SearchPath'])
        client_keys = ServiceKeys.read_from_file(keyfile, keypath)
    except Exception as e :
        raise Exception('unable to load client keys; {0}'.format(str(e)))

    # ---------- read the contract source code ----------
    try :
        source_path = state.get(['Contract', 'SourceSearchPath'])
        contract_code = pcontract.ContractCode.create_from_file(
            contract_class, source, source_path, interpreter=interpreter)
    except Exception as e :
        raise Exception('unable to load contract source; {0}'.format(str(e)))

    logger.debug('Loaded contract code for %s', contract_class)

    # ---------- set up the enclave clients ----------
    eservice_clients = eservice.get_eservice_list(state, eservice_group)
    if len(eservice_clients) == 0 :
        raise Exception('unable to locate enclave services in the group %s', eservice_group)

    preferred_eservice_client = eservice.get_eservice(state, eservice_group=eservice_group)
    if preferred_eservice_client.interpreter != interpreter :
        raise Exception('enclave interpreter does not match requested contract interpreter %s', interpreter)
    extra_data['preferred-enclave'] = preferred_eservice_client.enclave_id

    # ---------- set up the provisioning service clients ----------
    pservice_clients = pservice.get_pservice_list(state, pservice_group)
    if len(pservice_clients) == 0 :
        raise Exception('unable to locate provisioning services in the group %s', pservice_group)

    # ---------- register contract ----------
    data_directory = state.get(['Contract', 'DataDirectory'])
    ledger_config = state.get(['Ledger'])

    try :
        extra_params = {
            'num_provable_replicas' : replica_count,
            'availability_duration' : replica_duration,
            'replication_set' : replicas,
            'extra_data' : extra_data
        }

        provisioning_service_keys = [pc.identity for pc in pservice_clients]
        contract_id = pcontract.register_contract(
            ledger_config, client_keys, contract_code, provisioning_service_keys)

        logger.debug('Registered contract with class %s and id %s', contract_class, contract_id)
        contract_state = pcontract.ContractState.create_new_state(contract_id)
        contract = pcontract.Contract(contract_code, contract_state, contract_id, client_keys.identity, **extra_params)

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
## create_contract_from_context
## -----------------------------------------------------------------
def create_contract_from_context(state, context, default_class, **kwargs) :
    """create a contract pulling the parameters from a context
    """
    params = {}
    source = kwargs.get('source') or context['source']
    params['save_file'] = kwargs.get('save_file') or context['save_file']
    params['contract_class'] = kwargs.get('contact_class') or context['contract_class'] or default_class
    params['eservice_group'] = kwargs.get('eservice_group') or context['eservice_group']
    params['pservice_group'] = kwargs.get('pservice_group') or context['pservice_group']
    params['sservice_group'] = kwargs.get('sservice_group') or context['sservice_group']
    params['extra'] = kwargs.get('extra') or context['extra']

    return create_contract(state, source, **params)

## -----------------------------------------------------------------
## send_to_contract
## -----------------------------------------------------------------
def send_to_contract(state, message, save_file, **kwargs) :
    """Send a method invocation to a contract and commit any necessary state changes

    @param message: the invocation message, generally created from an invocation_request object
    @param save_file: file name for the local contract information
    @param eservice_url: identity of the eservice to use
    @param wait: flag to indicate that the invocation should be synchronous
    @param commit: flag to indicate that the results should be committed if appropriate
    @param key_file : name of the file storing the keys to use for the transactions
    """

    eservice_url = kwargs.get('eservice_url') or 'preferred'
    wait = kwargs.get('wait') or False
    commit = kwargs.get('commit') or True
    keyfile = kwargs.get('key_file') or state.private_key_file

    # ---------- load the invoker's keys ----------
    try :
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
    eservice_client = eservice.get_eservice_from_contract(state, save_file, eservice_url)

    # ---------- send the message to the enclave service ----------
    try :
        update_request = contract.create_update_request(client_keys, message, eservice_client)
        update_response = update_request.evaluate()
    except Exception as e:
        raise Exception('enclave failed to evaluate expression; {0}'.format(str(e)))

    if not update_response.status :
        raise ValueError(update_response.invocation_response)

    data_directory = state.get(['Contract', 'DataDirectory'])
    ledger_config = state.get(['Ledger'])

    if update_response.state_changed and commit :

        contract.set_state(update_response.raw_state)

        # asynchronously submit the commit task: (a commit task replicates
        # change-set and submits the corresponding transaction)
        try:
            update_response.commit_asynchronously(ledger_config)
        except Exception as e:
            raise Exception('failed to submit commit: %s', str(e))

        # wait for the commit to finish.
        # TDB:
        # 1. make wait_for_commit a separate shell command.
        # 2. Add a provision to specify commit dependencies as input to send command.
        # 3. Return commit_id after send command back to shell so as to use as input
        #    commit_dependency in a future send command
        try:
            txn_id = update_response.wait_for_commit()
            if txn_id is None:
                raise Exception("Did not receive txn id for the send operation")
        except Exception as e:
            raise Exception("Error while waiting for commit: %s", str(e))

        if wait :
            try :
                # we are trusting the submitter to handle polling of the ledger
                # and we dont care what the result is... if there is a result then
                # the state has been successfully committed
                submitter = create_submitter(ledger_config)
                encoded_state_hash = pcrypto.byte_array_to_base64(update_response.new_state_hash)
                _ = submitter.get_state_details(update_response.contract_id, encoded_state_hash)
            except Exception as e:
                raise Exception("Error while waiting for global commit: %s", str(e))

    return update_response.invocation_response

## -----------------------------------------------------------------
## COMMANDS
## -----------------------------------------------------------------
class script_command_info(pscript.script_command_base) :
    """Get information about a contract
    """

    name = "info"
    help = "Retrieve specific information about a contract object"

    fields = {
        'contract-id' : 'contract_id',
        'creator' : 'creator',
        'provisioned-enclaves' : 'provisioned_enclaves',
        'preferred-enclave' : 'preferred_enclave',
        'code-name' : 'code_name',
        'code-nonce' : 'code_nonce',
    }

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str, required=True)
        subparser.add_argument('--field', help='Field to return', type=str, choices=list(cls.fields.keys()), required=True)

    @classmethod
    def invoke(cls, state, bindings, save_file, field, **kwargs) :
        contract = get_contract(state, save_file)
        return getattr(contract, cls.fields[field])

## -----------------------------------------------------------------
class script_command_create(pscript.script_command_base) :
    """Create a new contract object
    """

    name = "create"
    help = "Create a contract object"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('-c', '--contract-class', help='Name of the contract class', type=str)
        subparser.add_argument('-e', '--eservice-group', help='Name of the enclave service group to use', type=str)
        subparser.add_argument('-f', '--save-file', help='File where contract data is stored', type=str)
        subparser.add_argument('-i', '--interpreter', help='Interpreter used to evaluate the contract', type=str)
        subparser.add_argument('-p', '--pservice-group', help='Name of the provisioning service group to use', type=str)
        subparser.add_argument('-r', '--sservice-group', help='Name of the storage service group to use', type=str)
        subparser.add_argument('--source', help='File that contains contract source code', required=True, type=str)
        subparser.add_argument('--extra', help='Extra data associated with the contract file', nargs=2, action='append')

    @classmethod
    def invoke(cls, state, bindings, source, **kwargs) :
        # if the key_file is set, then use it; otherwise, if the identity is set then
        # use the standard format for keys from identities
        if not kwargs.get('key_file') :
            if kwargs.get('identity') :
                kwargs['key_file'] = "{}_private.pem".format(kwargs.get('identity'))

        contract_id = create_contract(state, source, **kwargs)
        return contract_id

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_send(pscript.script_command_base) :
    """Send a message to a contract object
    """

    name = "send"
    help = "Send a message to a contract object"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-e', '--enclave',
            help='URL or name of the enclave service to use',
            type=str)

        subparser.add_argument(
            '-f', '--save-file',
            help='File where contract data is stored',
            required=True,
            type=str)

        # subparser.add_argument(
        #     '--identity',
        #     help='Name of the user key file',
        #     type=str)

        # subparser.add_argument(
        #     '--key-file',
        #     help='Name of the user key file',
        #     type=str)

        subparser.add_argument(
            '--wait',
            help='Wait for the transaction to commit',
            action='store_true')

        subparser.add_argument(
            '-p', '--positional',
            help='JSON-encoded positional parameters',
            type=invocation_parameter,
            nargs='+', action='extend')

        subparser.add_argument(
            '-k', '--kwarg',
            help='add a keyword argument and JSON encoded value to the invocation',
            type=invocation_parameter,
            nargs=2, action='append')

        subparser.add_argument(
            'method',
            help='message to be sent to the contract',
            type=str)

        subparser.add_argument(
            'params',
            help='parameters sent to the invocation',
            type=invocation_parameter,
            nargs='*')

    @classmethod
    def invoke(cls, state, bindings, method, save_file, **kwargs) :
        waitflag = kwargs.get('wait', False)

        pparams = kwargs.get('positional') or []

        kparams = dict()

        # if the key_file is set, then use it; otherwise, if the identity is set then
        # use the standard format for keys from identities
        if not kwargs.get('key_file') :
            if kwargs.get('identity') :
                kwargs['key_file'] = "{}_private.pem".format(kwargs.get('identity'))

        if kwargs.get('kwarg') :
            for (k, v) in kwargs.get('kwarg') :
                if type(k) is not str :
                    raise RuntimeError('expecting string key; {0}'.format(str(k)))
                kparams[k] = v

        # the parameters can be positional or keywords, a keyword parameter
        # separates the keyword from the value with a '='; note that positional
        # parameters must not contain an '='
        if kwargs.get('params') :
            for p in kwargs.get('params') :
                kvsplit = p.split('=',1)
                if len(kvsplit) == 1 :
                    pparams += kvsplit[0]
                elif len(kvsplit) == 2 :
                    kparams[kvsplit[0]] = kvsplit[1]


        message = pcontract.invocation_request(method, *pparams, **kparams)
        result = send_to_contract(state, message, save_file, **kwargs)

        return result

## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__subcommands__ = [
    script_command_info,
    script_command_create,
    script_command_send,
]
do_contract = pscript.create_shell_command('contract', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'contract', do_contract)
