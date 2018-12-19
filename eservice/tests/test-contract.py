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
import random
import pdo.test.helpers.secrets as secret_helper

import pdo.eservice.pdo_helper as enclave_helper
import pdo.service_client.enclave as eservice_helper
import pdo.service_client.provisioning as pservice_helper

import pdo.contract as contract_helper
import pdo.common.crypto as crypto
import pdo.common.keys as keys
import pdo.common.secrets as secrets
import pdo.common.utility as putils

import logging
logger = logging.getLogger(__name__)

# this will be used to test transaction dependencies
txn_dependencies = []

# representation of the enclave
enclave = None

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
        enclave_helper.shutdown()
    except Exception as e :
        logger.exception('shutdown failed')

    sys.exit(-1)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def CreateAndRegisterEnclave(config) :
    global enclave
    global txn_dependencies

    if use_eservice :
        try :
            eservice_url = random.choice(config['Service']['EnclaveServiceURLs'])
            logger.info('use enclave service at %s', eservice_url)
            enclave = eservice_helper.EnclaveServiceClient(eservice_url)
            return enclave
        except Exception as e :
            logger.error('failed to contact enclave service; %s', str(e))
            sys.exit(-1)

    enclave_config = config.get('EnclaveModule')
    ledger_config = config.get('Sawtooth')

    try :
        enclave_helper.initialize_enclave(enclave_config)
        enclave = enclave_helper.Enclave.create_new_enclave()
    except Exception as e :
        logger.error('failed to initialize the enclave; %s', str(e))
        sys.exit(-1)

    try :
        if use_ledger :
            txnid = enclave.register_enclave(ledger_config)
            txn_dependencies = [ txnid ]

            logger.info('enclave registration successful')

            enclave.verify_registration(ledger_config)
            logger.info('verified enclave registration')
        else :
            logger.debug('no ledger config; skipping enclave registration')
    except Exception as e :
        logger.exception('failed to register the enclave; %s', str(e))
        ErrorShutdown()

    return enclave

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def CreateAndRegisterContract(config, enclave, contract_creator_keys) :
    global txn_dependencies

    data_dir = config['Contract']['DataDirectory']

    ledger_config = config.get('Sawtooth')
    contract_creator_id = contract_creator_keys.identity

    try :
        contract_class = config['Contract']['Name']
        contract_source = config['Contract']['SourceFile']
        source_path = config['Contract']['SourceSearchPath']
        contract_code = contract_helper.ContractCode.create_from_scheme_file(contract_class, contract_source, source_path)
    except Exception as e :
        raise Exception('unable to load contract source; {0}'.format(str(e)))

    # create the provisioning servers
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
    if use_pservice :
        secret_list = []
        for pservice in provisioning_services :
            logger.debug('ask pservice %s to generate a secret for %s', pservice.ServiceURL, contract_id)
            message = enclave.enclave_id + contract_id
            signature = contract_creator_keys.sign(message, encoding='hex')
            secret = pservice.get_secret(enclave.enclave_id, contract_id, contract_creator_keys.verifying_key, signature)
            if secret is None :
                logger.error('failed to create secret for %s', pservice.ServiceURL)
                ErrorShutdown()
            secret_list.append(secret)
    else :
        secret_list = secret_helper.create_secrets_for_services(
            provisioning_services, enclave.enclave_keys, contract_id, contract_creator_id)

    logger.debug('secrets: %s', secret_list)

    try :
        secretinfo = enclave.verify_secrets(contract_id, contract_creator_id, secret_list)
        assert secretinfo

        encrypted_state_encryption_key = secretinfo['encrypted_state_encryption_key']
        signature = secretinfo['signature']

    except Exception as e :
        logger.error('failed to create the state encryption key; %s', str(e))
        ErrorShutdown()

    try :
        if not secrets.verify_state_encryption_key_signature(
                encrypted_state_encryption_key,
                secret_list,
                contract_id,
                contract_creator_id,
                signature,
                enclave.enclave_keys) :
            raise RuntimeError('signature verification failed')
    except Exception as e :
        logger.error('failed to verify the state encryption key; %s', str(e))
        ErrorShutdown()

    logger.info('encrypted state encryption key: %s', encrypted_state_encryption_key)

    # --------------------------------------------------
    logger.info('add the provisioned enclave to the contract')
    # --------------------------------------------------
    try :
        if use_ledger :
            txnid = contract_helper.add_enclave_to_contract(
                ledger_config,
                contract_creator_keys,
                contract_id,
                enclave.enclave_id,
                secret_list,
                encrypted_state_encryption_key,
                signature,
                transaction_dependency_list=txn_dependencies)
            txn_dependencies = [ txnid ]

            logger.info('contract state encryption key added to contract')
        else :
            logger.debug('no ledger config; skipping state encryption key registration')
    except Exception as e :
        logger.error('failed to add state encryption key; %s', str(e))
        ErrorShutdown()

    contract.set_state_encryption_key(enclave.enclave_id, encrypted_state_encryption_key)

    contract_save_file = config['Contract']['SaveFile']
    contract.save_to_file(contract_save_file, data_dir=data_dir)

    # --------------------------------------------------
    logger.info('create the initial contract state')
    # --------------------------------------------------
    try :
        initialize_request = contract.create_initialize_request(contract_creator_keys, enclave)
        initialize_response = initialize_request.evaluate()
        if initialize_response.status is False :
            logger.error('contract initialization failed: %s', initialize_response.result)
            ErrorShutdown()

        contract.set_state(initialize_response.encrypted_state)

    except Exception as e :
        logger.error('failed to create the initial state; %s', str(e))
        ErrorShutdown()

    logger.info('enclave created initial state')

    # --------------------------------------------------
    logger.info('save the initial state in the ledger')
    # --------------------------------------------------
    try :
        if use_ledger :
            logger.info("sending to ledger")
            # note that we will wait for commit of the transaction before
            # continuing; this is not necessary in general (if there is
            # confidence the transaction will succeed) but is useful for
            # testing
            txnid = initialize_response.submit_initialize_transaction(
                ledger_config,
                wait=30,
                transaction_dependency_list=txn_dependencies)
            txn_dependencies = [txnid]
        else:
            logger.debug('no ledger config; skipping iniatialize state save')
    except Exception as e :
        logger.error('failed to save the initial state; %s', str(e))
        ErrorShutdown()

    contract.contract_state.save_to_cache(data_dir=data_dir)

    return contract

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def UpdateTheContract(config, enclave, contract, contract_invoker_keys) :
    txn_dependencies = []

    ledger_config = config.get('Sawtooth')
    contract_invoker_id = contract_invoker_keys.identity

    with open(config['expressions'], "r") as efile :
        expressions = efile.readlines()

    start_time = time.time()
    for expression in expressions :
        expression = expression.strip()

        try :
            update_request = contract.create_update_request(contract_invoker_keys, enclave, expression)
            update_response = update_request.evaluate()
            if update_response.status is False :
                logger.info('failed: {0} --> {1}'.format(expression, update_response.result))
                continue

            logger.info('{0} --> {1}'.format(expression, update_response.result))

        except Exception as e:
            logger.error('enclave failed to evaluation expression; %s', str(e))
            ErrorShutdown()

        # if this operation did not change state then there is nothing
        # to send to the ledger or to save
        if not update_response.state_changed :
            continue

        try :
            if ledger_config is not None :
                logger.info("sending to ledger")
                # note that we will wait for commit of the transaction before
                # continuing; this is not necessary in general (if there is
                # confidence the transaction will succeed) but is useful for
                # testing
                txnid = update_response.submit_update_transaction(
                    ledger_config,
                    wait=30,
                    transaction_dependency_list = txn_dependencies)
                txn_dependencies = [ txnid ]
            else :
                logger.debug('no ledger config; skipping state save')
        except Exception as e :
            logger.error('failed to save the new state; %s', str(e))
            ErrorShutdown()

        logger.debug('update state')
        contract.set_state(update_response.encrypted_state)

    logger.info('completed in %s', time.time() - start_time)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def LocalMain(config) :
    # create the enclave
    ledger_config = config.get('Sawtooth')

    # keys of the contract creator
    contract_creator_keys = keys.ServiceKeys.create_service_keys()

    # --------------------------------------------------
    logger.info('create and register the enclave')
    # --------------------------------------------------
    enclave = CreateAndRegisterEnclave(config)

    # --------------------------------------------------
    logger.info('create the contract and register it')
    # --------------------------------------------------
    contract = CreateAndRegisterContract(config, enclave, contract_creator_keys)

    # --------------------------------------------------
    logger.info('invoke a few methods on the contract, load from file')
    # --------------------------------------------------
    data_dir = config['Contract']['DataDirectory']

    try :
        if use_ledger :
            logger.info('reload the contract from local file')
            contract_save_file = config['Contract']['SaveFile']
            contract = contract_helper.Contract.read_from_file(ledger_config, contract_save_file, data_dir=data_dir)
    except Exception as e :
        logger.error('failed to load the contract from a file; %s', str(e))
        ErrorShutdown()

    try :
        UpdateTheContract(config, enclave, contract, contract_creator_keys)
    except Exception as e :
        logger.error('contract execution failed; %s', str(e))
        ErrorShutdown()

    enclave_helper.shutdown()
    sys.exit(0)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## DO NOT MODIFY BELOW THIS LINE
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

## -----------------------------------------------------------------
ContractHost = os.environ.get("HOSTNAME", "localhost")
ContractHome = os.environ.get("CONTRACTHOME") or os.path.realpath("/opt/pdo")
ContractEtc = os.environ.get("CONTRACTETC") or os.path.join(ContractHome, "etc")
ContractKeys = os.environ.get("CONTRACTKEYS") or os.path.join(ContractHome, "keys")
ContractLogs = os.environ.get("CONTRACTLOGS") or os.path.join(ContractHome, "logs")
ContractData = os.environ.get("CONTRACTDATA") or os.path.join(ContractHome, "data")
LedgerURL = os.environ.get("LEDGER_URL", "http://127.0.0.1:8008/")
ScriptBase = os.path.splitext(os.path.basename(sys.argv[0]))[0]

config_map = {
    'base' : ScriptBase,
    'data' : ContractData,
    'etc'  : ContractEtc,
    'home' : ContractHome,
    'host' : ContractHost,
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

    import pdo.common.config as pconfig
    import pdo.common.logger as plogger

    # parse out the configuration file first
    conffiles = [ 'pcontract.toml', 'enclave.toml' ]
    confpaths = [ ".", "./etc", ContractEtc ]

    parser = argparse.ArgumentParser()

    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='directories to search for the configuration file', nargs = '+')

    parser.add_argument('-i', '--identity', help='Identity to use for the process', type=str)

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    parser.add_argument('--ledger', help='URL for the Sawtooth ledger', type=str)
    parser.add_argument('--no-ledger', help='Do not attempt ledger registration', action="store_true")

    parser.add_argument('--data-dir', help='Directory for storing generated files', type=str)
    parser.add_argument('--source-dir', help='Directories to search for contract source', nargs='+', type=str)
    parser.add_argument('--key-dir', help='Directories to search for key files', nargs='+')

    parser.add_argument('--eservice-url', help='List of enclave service URLs to use', nargs='+')
    parser.add_argument('--pservice-url', help='List of provisioning service URLs to use', nargs='+')

    parser.add_argument('--secret-count', help='Number of secrets to generate', type=int, default=3)
    parser.add_argument('--contract', help='Name of the contract to use', default='integer-key')
    parser.add_argument('--expressions', help='Name of a file to read for expressions', default=None)

    options = parser.parse_args()

    # first process the options necessary to load the default configuration
    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    # customize the configuration file for the current request
    global config_map

    config_map['identity'] = 'test-request'
    if options.identity :
        config_map['identity'] = options.identity

    if options.data_dir :
        config_map['data'] = options.data_dir

    config_map['contract'] = options.contract


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
    if config.get('Sawtooth') is None :
        config['Sawtooth'] = {
            'LedgerURL' : 'http://localhost:8008',
        }
    if options.ledger :
        config['Sawtooth']['LedgerURL'] = options.ledger

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
            'ProvisioningServiceURLs' : []
        }
    if options.eservice_url :
        use_eservice = True
        config['Service']['EnclaveServiceURLs'] = options.eservice_url
    if options.pservice_url :
        use_pservice = True
        config['Service']['ProvisioningServiceURLs'] = options.pservice_url

    # set up the data paths
    if config.get('Contract') is None :
        config['Contract'] = {
            'DataDirectory' : ContractData,
            'SourceSearchPath' : [ ".", "./contract", os.path.join(ContractHome,'contracts') ]
        }

    if options.data_dir :
        config['Contract']['DataDirectory'] = options.data_dir
    if options.source_dir :
        config['Contract']['SourceSearchPath'] = options.source_dir

    putils.set_default_data_directory(config['Contract']['DataDirectory'])

    if options.no_ledger  or not config['Sawtooth']['LedgerURL'] :
        use_ledger = False
        config.pop('Sawtooth', None)

    config['secrets'] = options.secret_count

    if options.expressions :
        expression_file = options.expressions
    else :
        expression_file = putils.build_simple_file_name(options.contract,'.exp')

    config['expressions'] = putils.find_file_in_path(expression_file, ['.', '..', 'contracts'])

    LocalMain(config)

Main()
