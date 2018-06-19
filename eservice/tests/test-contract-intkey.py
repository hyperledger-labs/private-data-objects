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
def CreateAndRegisterEnclave(config) :
    global enclave
    global txn_dependencies

    if use_eservice :
        eservice_url = config.get('eservice-url')
        logger.info('use enclave service at %s', eservice_url)
        enclave = eservice_helper.EnclaveServiceClient(eservice_url)
        return enclave

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
            logger.info('no ledger config; skipping enclave registration')
    except Exception as e :
        logger.exception('failed to register the enclave; %s', str(e))
        sys.exit(-1)

    return enclave

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def CreateAndRegisterContract(config, enclave, contract_creator_keys) :
    global txn_dependencies

    data_dir = config['PDO']['DataPath']

    ledger_config = config.get('Sawtooth')
    contract_creator_id = contract_creator_keys.identity

    contract_name = config['contract']
    contract_code = contract_helper.ContractCode.create_from_scheme_file(contract_name, search_path = [".", "..", "contracts"])

    # create the provisioning servers
    if use_pservice :
        pservice_urls = config.get("pservice-urls")
        provisioning_services = list(map(lambda url : pservice_helper.ProvisioningServiceClient(url), pservice_urls))
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
            logger.info('no ledger config; skipping contract registration')
    except Exception as e :
        logger.error('failed to register the contract; %s', str(e))
        sys.exit(-1)

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
                sys.exit(-1)
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
        sys.exit(-1)

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
        sys.exit(-1)

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
            logger.info('no ledger config; skipping state encryption key registration')
    except Exception as e :
        logger.error('failed to add state encryption key; %s', str(e))
        sys.exit(-1)

    contract.set_state_encryption_key(enclave.enclave_id, encrypted_state_encryption_key)
    contract.save_to_file(contract_name, data_dir=data_dir)

    # --------------------------------------------------
    logger.info('create the initial contract state')
    # --------------------------------------------------
    try :
        initialize_request = contract.create_initialize_request(contract_creator_keys, enclave)
        initialize_response = initialize_request.evaluate()
        if initialize_response.status is False :
            logger.error('contract initialization failed: %s', initialize_response.result)
            sys.exit(-1)

        contract.set_state(initialize_response.encrypted_state)

    except Exception as e :
        logger.error('failed to create the initial state; %s', str(e))
        sys.exit(-1)

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
            logger.info('no ledger config; skipping iniatialize state save')
    except Exception as e :
        logger.error('failed to save the initial state; %s', str(e))
        sys.exit(-1)

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
            sys.exit(-1)

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
                logger.info('no ledger config; skipping state save')
        except Exception as e :
            logger.error('failed to save the new state; %s', str(e))
            sys.exit(-1)

        contract.set_state(update_response.encrypted_state)

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
    data_dir = config['PDO']['DataPath']

    try :
        contract_name = config['contract']
        if use_ledger :
            logger.info('reload the contract from local file')
            contract = contract_helper.Contract.read_from_file(ledger_config, contract_name, data_dir=data_dir)
    except Exception as e :
        logger.error('failed to load the contract from a file; %s', str(e))
        sys.exit(-1)

    try :
        UpdateTheContract(config, enclave, contract, contract_creator_keys)
    except Exception as e :
        logger.error('contract execution failed; %s', str(e))
        sys.exit(-1)

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
ScriptBase = os.path.splitext(os.path.basename(sys.argv[0]))[0]

config_map = {
    'base' : ScriptBase,
    'data' : ContractData,
    'etc'  : ContractEtc,
    'home' : ContractHome,
    'host' : ContractHost,
    'keys' : ContractKeys,
    'logs' : ContractLogs
}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def ParseCommandLine(config, args) :
    global use_ledger, use_pservice, use_eservice

    parser = argparse.ArgumentParser()

    parser.add_argument('--ledger', help='URL for the Sawtooth ledger', type=str)
    parser.add_argument('--no-ledger', help='Do not attempt ledger registration', action="store_true")
    parser.add_argument('--data', help='Path for storing generated files', type=str)
    parser.add_argument('--secret-count', help='Number of secrets to generate', type=int, default=3)
    parser.add_argument('--contract', help='Name of the contract to use', default='integer-key')
    parser.add_argument('--expressions', help='Name of a file to read for expressions', default=None)
    parser.add_argument('--eservice', help='URL of the enclave service to use', type=str)
    parser.add_argument('--pservice', help='URLs for provisioning services to contact', type=str, nargs='+', default=[])

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    options = parser.parse_args(args)

    if config.get('Logging') is None :
        config['Logging'] = {
            'LogFile' : '__screen__',
            'LogLevel' : 'INFO'
        }
    if options.logfile :
        config['Logging']['LogFile'] = options.logfile
    if options.loglevel :
        config['Logging']['LogLevel'] = options.loglevel.upper()

    if config.get('PDO') is None :
        config['PDO'] = {
            'DataPath' : 'mock_data',
            'SchemeSearchPath' : ['contracts']
        }
    if options.data :
        config['PDO']['DataPath'] = options.data

    if config.get('Sawtooth') is None :
        config['Sawtooth'] = {
            'LedgerURL' : 'http://localhost:8008',
            'Organization' : 'Organization'
        }
    if options.ledger :
        config['Sawtooth']['LedgerURL'] = options.ledger

    if options.no_ledger :
        use_ledger = False
        config.pop('Sawtooth', None)

    if options.eservice :
        use_eservice = True
        config['eservice-url'] = options.eservice

    if options.pservice :
        use_pservice = True
        config['pservice-urls'] = options.pservice

    config['secrets'] = options.secret_count
    config['contract'] = options.contract

    if options.expressions :
        expression_file = options.expressions
    else :
        expression_file = config['contract'] + '.exp'

    config['expressions'] = putils.find_file_in_path(expression_file, ['.', '..', 'contracts'])

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def Main() :
    import pdo.common.config as pconfig
    import pdo.common.logger as plogger

    # parse out the configuration file first
    conffiles = [ 'eservice_tests.toml' ]
    confpaths = [ ".", "./etc", ContractEtc ]

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='configuration file', nargs = '+')
    (options, remainder) = parser.parse_known_args()

    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    global config_map
    config_map['identity'] = 'test-request'

    try :
        config = pconfig.parse_configuration_files(conffiles, confpaths, config_map)
    except pconfig.ConfigurationException as e :
        logger.error(str(e))
        sys.exit(-1)

    ParseCommandLine(config, remainder)

    plogger.setup_loggers(config.get('Logging', {}))
    sys.stdout = plogger.stream_to_logger(logging.getLogger('STDOUT'), logging.DEBUG)
    sys.stderr = plogger.stream_to_logger(logging.getLogger('STDERR'), logging.WARN)

    LocalMain(config)

Main()
