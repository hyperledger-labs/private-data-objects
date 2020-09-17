#!/usr/bin/env python

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
import sys
import time
import argparse

from string import Template

import pdo.test.helpers.secrets as secret_helper
import pdo.test.helpers.state as test_state

from pdo.sservice.block_store_manager import BlockStoreManager

import pdo.eservice.pdo_helper as enclave_helper
import pdo.service_client.enclave as eservice_helper
import pdo.service_client.provisioning as pservice_helper
import pdo.service_client.service_data.eservice as db

import pdo.contract as contract_helper
from pdo.contract.response import ContractResponse
import pdo.common.crypto as crypto
import pdo.common.keys as keys
import pdo.common.secrets as secrets
import pdo.common.utility as putils

import logging
logger = logging.getLogger(__name__)

# representation of the enclave
enclave = None
block_store = None

use_ledger = True
use_eservice = False
use_pservice = False

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def ErrorShutdown() :
    """
    Perform a clean shutdown after an error
    """
    try :
        if block_store is not None :
            block_store.close()
    except Exception as e :
        logger.exception('failed to close block_store')

    try :
        enclave_helper.shutdown_enclave()
    except Exception as e :
        logger.exception('shutdown failed')

    # Send termination signal to commit tasks
    ContractResponse.exit_commit_workers()

    sys.exit(-1)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def AddReplicationParamsToContract(config, enclave_clients, contract):
    """ Get parameters for change set replication from config. """

    replication_config = config['Replication']

    # ---------- get replication parameters from config --------------------------------------------------

    try :
        num_provable_replicas = replication_config['NumProvableReplicas']
        availability_duration = replication_config['Duration']
    except Exception as e :
        logger.error('Replication is enabled with incomplete configuration.')
        sys.exit(-1)

    assert num_provable_replicas >= 0 , "Invalid configuration for num_provable_replicas: Must be a postive integer for proof of replication "
    assert num_provable_replicas <= len(enclave_clients), "Invalid configuration for num_provable_replicas : Can be at most number of provisioned eservices"
    assert availability_duration > 0 , "Invalid configuration for availability duration: Must be positive."

    contract.set_replication_parameters(num_provable_replicas, availability_duration)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def AddEnclaveSecrets(ledger_config, contract_id, client_keys, enclaves, provclients) :
    secrets = {}
    encrypted_state_encryption_keys = {}
    for enclave in enclaves:

        if use_pservice:
            psecrets = []
            for provclient in provclients:
                # Get a pspk:esecret pair from the provisioning service for each enclave
                sig_payload = crypto.string_to_byte_array(enclave.enclave_id + contract_id)
                secretinfo = provclient.get_secret(enclave.enclave_id,
                                               contract_id,
                                               client_keys.verifying_key,
                                               client_keys.sign(sig_payload))
                logger.debug("pservice secretinfo: %s", secretinfo)

                # Add this pspk:esecret pair to the list
                psecrets.append(secretinfo)
        else:
            psecrets = secret_helper.create_secrets_for_services(provclients, enclave.enclave_keys, contract_id, client_keys.identity)

        # Print all of the secret pairs generated for this particular enclave
        logger.debug('psecrets for enclave %s : %s', enclave.enclave_id, psecrets)

        # Verify those secrets with the enclave
        esresponse = enclave.verify_secrets(contract_id, client_keys.verifying_key, psecrets)
        logger.debug("verify_secrets response: %s", esresponse)

        # Store the ESEK mapping in a dictionary key'd by the enclave's public key (ID)
        encrypted_state_encryption_keys[enclave.enclave_id] = esresponse['encrypted_state_encryption_key']

        # Add this spefiic enclave to the contract
        if use_ledger :
            contract_helper.add_enclave_to_contract(ledger_config,
                                client_keys,
                                contract_id,
                                enclave.enclave_id,
                                psecrets,
                                esresponse['encrypted_state_encryption_key'],
                                esresponse['signature']
                                )

    return encrypted_state_encryption_keys

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def CreateAndRegisterEnclave(config) :
    """
    creates and registers an enclave
    IMPORTANT: if an eservice is available it will be used,
               otherwise, the code interfaces directly with the python/swig wrapper in the eservice code
    """

    global enclave
    ledger_config = config.get('Ledger')

    interpreter = config['Contract']['Interpreter']

    # if we are using the eservice then there is nothing to register since
    # the eservice has already registered the enclave
    if use_eservice :
        enclaveclients = []
        try :
            for url in config['Service']['EnclaveServiceURLs'] :
                einfo = db.add_by_url(ledger_config, url)
                logger.debug('interpreter is %s', einfo.client.interpreter)
                assert einfo.client.interpreter == interpreter
                enclaveclients.append(einfo.client)
        except Exception as e :
            logger.error('unable to setup enclave services; %s', str(e))
            sys.exit(-1)
        return enclaveclients

    # not using an eservice so build the local enclave
    try :
        global block_store
        block_store_file = config['StorageService']['BlockStore']
        block_store = BlockStoreManager(block_store_file, create_block_store=True)
    except Exception as e :
        logger.error('failed to initialize the block store; %s', str(e))
        sys.exit(-1)

    try :
        enclave_helper.initialize_enclave(config)
        enclave = enclave_helper.Enclave.create_new_enclave()
    except Exception as e :
        logger.exception('failed to initialize the enclave; %s', str(e))
        block_store.close()
        sys.exit(-1)

    if enclave.interpreter != interpreter :
        logger.error('contract and enclave expect different interpreters; %s != %s', enclave.interpreter, interpreter)
        ErrorShutdown()

    try :
        enclave.attach_block_store(block_store)
    except Exception as e :
        logger.exception('failed to attach block store; %s', str(e))
        ErrorShutdown()

    try :
        if use_ledger :
            txnid = enclave.register_enclave(ledger_config)
            logger.info('enclave registration successful')

            enclave.verify_registration(ledger_config)
            logger.info('verified enclave registration')
        else :
            logger.debug('no ledger config; skipping enclave registration')
    except Exception as e :
        logger.exception('failed to register the enclave; %s', str(e))
        ErrorShutdown()

    return [enclave]

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def CreateAndRegisterContract(config, enclaves, contract_creator_keys) :

    data_dir = config['Contract']['DataDirectory']

    ledger_config = config.get('Ledger')
    contract_creator_id = contract_creator_keys.identity

    try :
        contract_class = config['Contract']['Name']
        contract_source = config['Contract']['SourceFile']
        source_path = config['Contract']['SourceSearchPath']
        interpreter = config['Contract']['Interpreter']
        contract_code = contract_helper.ContractCode.create_from_file(contract_class, contract_source, source_path, interpreter=interpreter)
    except Exception as e :
        raise Exception('unable to load contract source; {0}'.format(str(e)))

    # create the provisioning service clients
    if use_pservice :
        try :
            pservice_urls = config['Service']['ProvisioningServiceURLs']
            provisioning_services = list(map(lambda url : pservice_helper.ProvisioningServiceClient(url), pservice_urls))
        except Exception as e :
            logger.error('failed to connect to provisioning service; %s', str(e))
            ErrorShutdown()
    else :
        provisioning_services = secret_helper.create_provisioning_services(config['secrets'])
    provisioning_service_keys = list(map(lambda svc : svc.identity, provisioning_services))

    # register the contract, get contract_id
    try :
        if use_ledger :
            contract_id = contract_helper.register_contract(
                ledger_config, contract_creator_keys, contract_code, provisioning_service_keys)
            logger.info('contract registration successful; %s', contract_id)
        else :
            contract_id = crypto.byte_array_to_base64(crypto.compute_message_hash(crypto.random_bit_string(256)))
            logger.debug('no ledger config; skipping contract registration')
    except Exception as e :
        logger.error('failed to register the contract; %s', str(e))
        ErrorShutdown()

    contract_state = contract_helper.ContractState.create_new_state(contract_id)
    contract = contract_helper.Contract(contract_code, contract_state, contract_id, contract_creator_id)

    # --------------------------------------------------
    logger.info('create the provisioning secrets')
    # --------------------------------------------------
    encrypted_state_encryption_keys = AddEnclaveSecrets(
        ledger_config, contract.contract_id, contract_creator_keys, enclaves, provisioning_services)

    for enclave_id in encrypted_state_encryption_keys :
        encrypted_key = encrypted_state_encryption_keys[enclave_id]
        contract.set_state_encryption_key(enclave_id, encrypted_key)

    # add replication information to contract
    AddReplicationParamsToContract(config, enclaves, contract)

    # Decide if the contract uses a fixed enclave or a randomized one for each update. If fixed, we chose here. If random,
    # will be selected at random during request creation
    if use_eservice and config['Service']['Randomize_Eservice']:
        enclave_to_use = 'random'
    else:
        enclave_to_use = enclaves[0]

    # save the contract info as a pdo file
    contract_save_file = '_' + contract.short_id + '.pdo'
    contract.save_to_file(contract_save_file, data_dir=data_dir)

    # --------------------------------------------------
    logger.info('create the initial contract state')
    # --------------------------------------------------
    try :
        initialize_request = contract.create_initialize_request(contract_creator_keys, enclave_to_use)
        initialize_response = initialize_request.evaluate()
        if initialize_response.status is False :
            logger.error('contract initialization failed: %s', initialize_response.invocation_response)
            ErrorShutdown()

        contract.set_state(initialize_response.raw_state)

    except Exception as e :
        logger.exception('failed to create the initial state; %s', str(e))
        ErrorShutdown()

    logger.info('enclave created initial state')

    # submit the commit task: (a commit task replicates change-set and submits the corresponding transaction)
    try:
        initialize_response.commit_asynchronously(ledger_config)
    except Exception as e:
        logger.exception('failed to asynchronously start replication and transaction submission:' + str(e))
        ErrorShutdown()

    # wait for the commit to finish.
    try:
        txn_id = initialize_response.wait_for_commit()
        if use_ledger and txn_id is None:
            logger.error("Did not receive txn id for the initial commit")
            ErrorShutdown()
    except Exception as e:
        logger.error("Error while waiting for initial commit: %s", str(e))
        ErrorShutdown()

    logger.debug('update state')
    contract.contract_state.save_to_cache(data_dir=data_dir)

    return contract

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def UpdateTheContract(config, contract, enclaves, contract_invoker_keys) :

    ledger_config = config.get('Ledger')
    contract_invoker_id = contract_invoker_keys.identity
    last_response_committed = None

    # Decide if the contract use a fixed enclave or a randomized one for each update.
    if use_eservice and config['Service']['Randomize_Eservice']:
        enclave_to_use = 'random'
    else:
        enclave_to_use = enclaves[0]

    start_time = time.time()
    for x in range(config['iterations']) :
        if tamper_block_order :
            # in this evaluation we tamper with the state, so it should fail with a bad authenticator error
            logger.info('the following evaluation should fail with a bad authenticator error')
            temp_saved_state_hash = contract.contract_state.get_state_hash(encoding='b64')
            test_state.TamperWithStateBlockOrder(contract.contract_state)

        try :
            expression = contract_helper.invocation_request('inc_value')
            update_request = contract.create_update_request(contract_invoker_keys, expression, enclave_to_use)
            update_response = update_request.evaluate()

            if update_response.status is False :
                logger.info('failed: {0} --> {1}'.format(expression, update_response.invocation_response))
                continue

            logger.info('{0} --> {1}'.format(expression, update_response.invocation_response))

        except Exception as e:
            logger.error('enclave failed to evaluate expression; %s', str(e))
            ErrorShutdown()

        # if this operation did not change state then there is nothing to commit
        if update_response.state_changed :
            # asynchronously submit the commit task: (a commit task replicates change-set and submits the corresponding transaction)
            try:
                update_response.commit_asynchronously(ledger_config)
                last_response_committed = update_response
            except Exception as e:
                logger.error('failed to submit commit: %s', str(e))
                ErrorShutdown()

            logger.debug('update state')
            contract.set_state(update_response.raw_state)

    # wait for the last commit to finish.
    if last_response_committed is not None:
        try:
            txn_id = last_response_committed.wait_for_commit()
            if use_ledger and txn_id is None:
                logger.error("Did not receive txn id for the last response committed")
                ErrorShutdown()
        except Exception as e:
            logger.error("Error while waiting for the last response committed: %s", str(e))
            ErrorShutdown()

    logger.info("All commits completed")
    logger.info('completed in %s', time.time() - start_time)

    # shutdown commit workers
    ContractResponse.exit_commit_workers()

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def LocalMain(config) :
    # create the enclave
    ledger_config = config.get('Ledger')

    # keys of the contract creator
    contract_creator_keys = keys.ServiceKeys.create_service_keys()

    # --------------------------------------------------
    logger.info('create and register the enclaves')
    # --------------------------------------------------
    enclaves  = CreateAndRegisterEnclave(config)

    # --------------------------------------------------
    logger.info('create the contract and register it')
    # --------------------------------------------------
    contract = CreateAndRegisterContract(config, enclaves, contract_creator_keys)

    # --------------------------------------------------
    logger.info('invoke a few methods on the contract, load from file')
    # --------------------------------------------------
    data_dir = config['Contract']['DataDirectory']

    try :
        if use_ledger :
            logger.info('reload the contract from local file')
            contract_save_file = '_' + contract.short_id + '.pdo'
            contract = contract_helper.Contract.read_from_file(ledger_config, contract_save_file, data_dir=data_dir)
            logger.info("read the contract")
    except Exception as e :
        logger.error('failed to load the contract from a file; %s', str(e))
        ErrorShutdown()

    try :
        UpdateTheContract(config, contract, enclaves, contract_creator_keys)
    except Exception as e :
        logger.exception('contract execution failed; %s', str(e))
        ErrorShutdown()
    
    enclave_helper.shutdown_enclave()
    sys.exit(0)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## DO NOT MODIFY BELOW THIS LINE
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

## -----------------------------------------------------------------
ContractHost = os.environ.get("PDO_HOSTNAME", "localhost")
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
ContractEtc = os.path.join(ContractHome, "etc")
ContractKeys = os.path.join(ContractHome, "keys")
ContractLogs = os.path.join(ContractHome, "logs")
ContractData = os.path.join(ContractHome, "data")
ContractInterpreter = os.environ.get("PDO_INTERPRETER", "gipsy")
LedgerURL = os.environ.get("PDO_LEDGER_URL", "http://127.0.0.1:8008/")
ScriptBase = os.path.splitext(os.path.basename(sys.argv[0]))[0]

config_map = {
    'base' : ScriptBase,
    'data' : ContractData,
    'etc'  : ContractEtc,
    'home' : ContractHome,
    'host' : ContractHost,
    'interpreter' : ContractInterpreter,
    'keys' : ContractKeys,
    'logs' : ContractLogs,
    'ledger' : LedgerURL
}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def Main() :
    global use_ledger
    global use_eservice
    global use_pservice
    global tamper_block_order

    import pdo.common.config as pconfig
    import pdo.common.logger as plogger

    # parse out the configuration file first
    conffiles = [ 'pcontract.toml', 'enclave.toml', 'eservice1.toml' ]
    confpaths = [ ".", "./etc", ContractEtc ]

    parser = argparse.ArgumentParser()

    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='directories to search for the configuration file', nargs = '+')

    parser.add_argument('-i', '--identity', help='Identity to use for the process', default='test-request', type=str)

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    parser.add_argument('--ledger', help='URL for the Sawtooth ledger', type=str)
    parser.add_argument('--no-ledger', help='Do not attempt ledger registration', action="store_true")

    parser.add_argument('--data-dir', help='Directory for storing generated files', type=str)
    parser.add_argument('--source-dir', help='Directories to search for contract source', nargs='+', type=str)
    parser.add_argument('--key-dir', help='Directories to search for key files', nargs='+')

    parser.add_argument('--eservice-url', help='List of enclave service URLs to use', nargs='+')
    parser.add_argument('--randomize-eservice', help="Randomize eservice used for each update", action="store_true")

    parser.add_argument('--pservice-url', help='List of provisioning service URLs to use', nargs='+')

    parser.add_argument('--block-store', help='Name of the file where blocks are stored', type=str)

    parser.add_argument('--secret-count', help='Number of secrets to generate', type=int, default=3)
    parser.add_argument('--interpreter', help='Name of the contract to to require', default=ContractInterpreter)
    parser.add_argument('--iterations', help='Number of operations to perform', type=int, default=10)

    parser.add_argument('--num-provable-replicas', help='Number of sservice signatures needed for proof of replication', type=int, default=1)
    parser.add_argument('--availability-duration', help='duration (in seconds) for which the replicas are stored at storage service', type=int, default=60)

    parser.add_argument('--tamper-block-order', help='Flag for tampering with the order of the state blocks', action='store_true')

    options = parser.parse_args()

    # first process the options necessary to load the default configuration
    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    # customize the configuration file for the current request
    global config_map

    config_map['identity'] = options.identity

    if options.data_dir :
        config_map['data'] = options.data_dir

    # parse the configuration file
    try :
        config = pconfig.parse_configuration_files(conffiles, confpaths, config_map)
    except pconfig.ConfigurationException as e :
        logger.error(str(e))
        sys.exit(-1)

    # set up the logging configuration
    if config.get('Logging') is None :
        config['Logging'] = {
            'LogFile' : '__screen__',
            'LogLevel' : 'INFO'
        }
    if options.logfile :
        config['Logging']['LogFile'] = options.logfile
    if options.loglevel :
        config['Logging']['LogLevel'] = options.loglevel.upper()

    plogger.setup_loggers(config.get('Logging', {}))
    sys.stdout = plogger.stream_to_logger(logging.getLogger('STDOUT'), logging.DEBUG)
    sys.stderr = plogger.stream_to_logger(logging.getLogger('STDERR'), logging.WARN)

    # set up the ledger configuration
    if config.get('Ledger') is None :
        config['Ledger'] = {
            'LedgerURL' : 'http://localhost:8008',
        }
    if options.ledger :
        config['Ledger']['LedgerURL'] = options.ledger
    if options.no_ledger  or not config['Ledger']['LedgerURL'] :
        use_ledger = False
        config.pop('Ledger', None)

    # set up the key search paths
    if config.get('Key') is None :
        config['Key'] = {
            'SearchPath' : ['.', './keys', ContractKeys],
            'FileName' : options.identity + ".pem"
        }
    if options.key_dir :
        config['Key']['SearchPath'] = options.key_dir

    # set up the service configuration
    if config.get('Service') is None :
        config['Service'] = {
            'EnclaveServiceURLs' : [],
            'ProvisioningServiceURLs' : [],
            'EnclaveServiceDatabaseFile' : None,
            'Randomize_Eservice' : False
        }

    if options.randomize_eservice:
        config['Service']['Randomize_Eservice'] = True
    else:
        config['Service']['Randomize_Eservice'] = False
    if options.eservice_url :
        use_eservice = True
        config['Service']['EnclaveServiceURLs'] = options.eservice_url
    if options.pservice_url :
        use_pservice = True
        config['Service']['ProvisioningServiceURLs'] = options.pservice_url

    # replication parameters
    if options.num_provable_replicas :
        config['Replication']['NumProvableReplicas'] = options.num_provable_replicas
    if options.availability_duration :
        config['Replication']['Duration'] = options.availability_duration

    # set up the data paths
    if config.get('Contract') is None :
        config['Contract'] = {
            'DataDirectory' : ContractData,
            'SourceSearchPath' : [ ".", "./contract", os.path.join(ContractHome,'contracts') ]
        }

    config['Contract']['Interpreter'] = options.interpreter
    config['Contract']['Name'] = 'mock-contract'
    config['Contract']['SourceFile'] = '_mock-contract'

    if options.data_dir :
        config['Contract']['DataDirectory'] = options.data_dir
    if options.source_dir :
        config['Contract']['SourceSearchPath'] = options.source_dir

    putils.set_default_data_directory(config['Contract']['DataDirectory'])

    # set up the storage service configuration
    if config.get('StorageService') is None :
        config['StorageService'] = {
            'BlockStore' : os.path.join(config['Contract']['DataDirectory'], options.identity + '.mdb'),
        }
    if options.block_store :
        config['StorageService']['BlockStore'] = options.block_store

    config['secrets'] = options.secret_count
    config['iterations'] = options.iterations

    tamper_block_order = options.tamper_block_order
    if tamper_block_order :
        config['iterations'] = 1


    LocalMain(config)

Main()
