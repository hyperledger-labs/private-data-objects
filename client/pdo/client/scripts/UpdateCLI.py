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

import argparse
import os
import sys
import random
import logging
logger = logging.getLogger(__name__)

import pdo.common.utility as putils
from pdo.contract import Contract
from pdo.common.keys import ServiceKeys
from pdo.service_client.enclave import EnclaveServiceClient
import pdo.service_client.service_data.eservice as db
from pdo.contract.response import ContractResponse

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class MessageIterator(object) :
    def __init__(self, message) :
        self.Message = [ message ]

    def __iter__(self) :
        return self

    def __next__(self) :
        if self.Message :
            return self.Message.pop(0).strip()
        else :
            raise StopIteration

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class InputIterator(object) :
    def __init__(self, prompt = "> ") :
        self.Prompt = prompt

    def __iter__(self) :
        return self

    def __next__(self) :
        try :
            return input(self.Prompt)
        except EOFError as e :
            raise StopIteration

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def LocalMain(config, message) :
    # ---------- check the integrity of the configuration ----------
    try :
        ledger_config = config['Sawtooth']
        contract_config = config['Contract']
        service_config = config['Service']
        key_config = config['Key']
    except KeyError as ke :
        logger.error('missing configuration section %s', str(ke))
        sys.exit(-1)

    # ---------- load the eservice database ----------
    if os.path.exists(service_config['EnclaveServiceDatabaseFile']):
        logger.info('loading eservice database')
        try:
            db.load_database(service_config['EnclaveServiceDatabaseFile'])
        except Exception as e:
            logger.error('Error loading eservice database %s', str(e))
            sys.exit(-1)

    # ---------- load the contract information file ----------
    try:
        save_file = contract_config['SaveFile']
        data_directory = contract_config['DataDirectory']
        logger.info('load contract from %s', save_file)

        contract = Contract.read_from_file(ledger_config, save_file, data_dir=data_directory)
    except KeyError as ke :
        logger.error('missing configuration parameter %s', str(ke))
        sys.exit(-1)
    except Exception as e:
        logger.error('failed to load the contract; %s', str(e))
        sys.exit(-1)

    # ---------- load the invoker's keys ----------
    try :
        keyfile = key_config['FileName']
        keypath = key_config['SearchPath']
        contract_invoker_keys = ServiceKeys.read_from_file(keyfile, keypath)
    except KeyError as ke :
        logger.error('missing configuration parameter %s', str(ke))
        sys.exit(-1)
    except Exception as e :
        logger.error('unable to load client keys; %s', str(e))
        sys.exit(-1)

    # ---------- set up the enclave service ----------
    if service_config.get('EnclaveServiceNames'): #use the database to get the enclave for the contract
        logger.info('Using eservice database to look up service URL for the contract enclave')
        try:
            eservice_to_use = random.choice(service_config['EnclaveServiceNames'])
            enclave_client = db.get_client_by_name(eservice_to_use)
        except Exception as e:
            logger.error('Unable to get the eservice client using the eservice database: %s', str(e))
            sys.exit(-1)
    else:
        try:
            enclave_url = service_config['PreferredEnclaveService']
        except Exception as e:
            logger.error('missing configuration parameter %s', str(ke))
            sys.exit(-1)
        try :
            enclave_client = EnclaveServiceClient(enclave_url)
        except Exception as e :
            logger.error('unable to connect to enclave service; %s', str(e))
            sys.exit(-1)

    logger.info('contact enclave service at %s', enclave_client.ServiceURL)

    try :
        # this is just a sanity check to make sure the selected enclave
        # has actually been provisioned
        contract.get_state_encryption_key(enclave_client.enclave_id)
    except KeyError as ke :
        logger.error('selected enclave is not provisioned')
        sys.exit(-1)

    # ---------- process incoming messages ----------
    if message :
        mlist = MessageIterator(message)
    else :
        mlist = InputIterator(config.get('Identity', '') + "> ")

    last_response_committed = None
    for msg in mlist :
        if not msg :
            continue

        logger.info('send message <%s> to contract', msg)

        try :
            update_request = contract.create_update_request(contract_invoker_keys, msg, enclave_client)
            update_response = update_request.evaluate()
            if update_response.status :
                print(update_response.result)
            else :
                print('ERROR: {}'.format(update_response.result))
                # continue if this is an interactive session, fail
                # if we are processing command line messages
                if message :
                    sys.exit(-1)
                else :
                    continue
        except Exception as e:
            logger.error('enclave failed to evaluation expression; %s', str(e))
            sys.exit(-1)

        # if this operation did not change state then there is nothing
        # to send to the ledger or to save
        if not update_response.state_changed :
            continue

        contract.set_state(update_response.raw_state)

        # asynchronously submit the commit task: (a commit task replicates change-set and submits the corresponding transaction)
        try:
            update_response.commit_asynchronously(ledger_config)
            last_response_committed = update_response
        except Exception as e:
            logger.error('failed to submit commit: %s', str(e))
            ContractResponse.exit_commit_workers()
            sys.exit(-1)

        contract.contract_state.save_to_cache(data_dir = data_directory)

    if last_response_committed is not None:
        # wait for the last commit to finish
        try:
            txn_id = last_response_committed.wait_for_commit()
            if txn_id is None:
                logger.error("Did not receive txn id for the final commit")
                ContractResponse.exit_commit_workers()
                sys.exit(-1)
        except Exception as e:
            logger.error("Error while waiting for final commit: %s", str(e))
            ContractResponse.exit_commit_workers()
            sys.exit(-1)

    ContractResponse.exit_commit_workers()
    sys.exit(0)


## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## DO NOT MODIFY BELOW THIS LINE
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

## -----------------------------------------------------------------
ContractHost = os.environ.get("HOSTNAME", "localhost")
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
ContractEtc = os.path.join(ContractHome, "etc")
ContractKeys = os.path.join(ContractHome, "keys")
ContractLogs = os.path.join(ContractHome, "logs")
ContractData = os.path.join(ContractHome, "data")
LedgerURL = os.environ.get("PDO_LEDGER_URL", "http://127.0.0.1:8008/")
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
    import pdo.common.config as pconfig
    import pdo.common.logger as plogger

    # parse out the configuration file first
    conffiles = [ 'pcontract.toml' ]
    confpaths = [ ".", "./etc", ContractEtc ]

    parser = argparse.ArgumentParser()

    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='configuration file', nargs = '+')

    parser.add_argument('--identity', help='Identity to use for the process', type=str, required=True)

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    parser.add_argument('--ledger', help='URL for the Sawtooth ledger', type=str)
    parser.add_argument('--save-file', help='Name of the file where contract data is stored', type=str, required=True)

    parser.add_argument('--key-dir', help='Directories to search for key files', nargs='+')
    parser.add_argument('--data-dir', help='Path for storing generated files', type=str)
    parser.add_argument('--source-dir', help='Directories to search for contract source', nargs='+', type=str)

    parser.add_argument('--eservice-name', help='List of enclave services to use. Give names as in database.', nargs='+')
    parser.add_argument('--enclave', help='URL of the enclave service to use, or say "random" to pick one randomly from pcontract.toml', type=str)
    parser.add_argument('--eservice-db', help='json file for eservice database', type=str)

    parser.add_argument('message', help="Message to evaluate", type=str)

    options = parser.parse_args()

    # first process the options necessary to load the default configuration
    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    global config_map
    config_map['identity'] = options.identity
    config_map['contract'] = '__unknown__'
    if options.data_dir :
        config_map['data'] = options.data_dir

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

    # set up the ledger configuration
    if config.get('Sawtooth') is None :
        config['Sawtooth'] = {
            'LedgerURL' : 'http://localhost:8008',
        }
    if options.ledger :
        config['Sawtooth']['LedgerURL'] = options.ledger

    # set up the service configuration
    if config.get('Service') is None :
        config['Service'] = {
            'EnclaveServiceNames' : [],
            'PreferredEnclaveService' : 'http://127.0.0.1:7101',
            'EnclaveServiceURLs' : [],
            'ProvisioningServiceURLs' : [],
            'EnclaveServiceDatabaseFile' : None
        }

    if options.eservice_name:
        config['Service']['EnclaveServiceNames'] = options.eservice_name
    if options.eservice_db:
        config['Service']['EnclaveServiceDatabaseFile'] = options.eservice_db
    if options.enclave :
        if options.enclave == 'random' :
            options.enclave = random.choice(config['Service'].get('EnclaveServiceURLs',['http://localhost:7001']))
        config['Service']['PreferredEnclaveService'] = options.enclave
        # we will not use database
        config['Service']['EnclaveServiceNames'] = []

    # set up the key search paths
    if config.get('Key') is None :
        config['Key'] = {
            'SearchPath' : ['.', './keys', ContractKeys],
            'FileName' : options.identity + ".pem"
        }
    if options.key_dir :
        config['Key']['SearchPath'] = options.key_dir

    # set up the data paths
    if config.get('Contract') is None :
        config['Contract'] = {
            'DataDirectory' : ContractData,
            'SaveFile' : options.save_file
        }

    config['Contract']['SaveFile'] = options.save_file
    if options.data_dir :
        config['Contract']['DataDirectory'] = options.data_dir
    if options.source_dir :
        config['Contract']['SourceSearchPath'] = options.source_dir

    putils.set_default_data_directory(config['Contract']['DataDirectory'])

    # GO!
    LocalMain(config, options.message)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
