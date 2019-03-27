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

import os, sys
import logging
import argparse
import random
import json


import pdo.common.config as pconfig
import pdo.common.logger as plogger
import pdo.common.crypto as pcrypto
import pdo.common.utility as putils

from pdo.common.keys import ServiceKeys
from pdo.contract import ContractCode
from pdo.contract import ContractState
from pdo.contract import Contract
from pdo.contract import register_contract
from pdo.contract import add_enclave_to_contract
from pdo.service_client.enclave import EnclaveServiceClient
from pdo.service_client.provisioning import ProvisioningServiceClient

logger = logging.getLogger(__name__)

## -----------------------------------------------------------------
def AddEnclaveSecrets(ledger_config, contract_id, client_keys, enclaveclients, provclients) :
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
def CreateContract(ledger_config, client_keys, enclaveclients, contract) :
    # Choose one enclave at random to use to create the contract
    enclaveclient = random.choice(enclaveclients)

    logger.info('Requesting that the enclave initialize the contract...')
    initialize_request = contract.create_initialize_request(client_keys, enclaveclient)
    initialize_response = initialize_request.evaluate()
    contract.set_state(initialize_response.raw_state)

    logger.info('Contract state created successfully')

    logger.info('Saving the initial contract state in the ledger...')

    cclinit_result = initialize_response.submit_initialize_transaction(ledger_config)

def are_the_urls_same(url1, url2):
    # OK, we need a better way to compare URLS than the string comparison used here. 
    # Ideally, one should normalize urls, and also resolve hostname to ip address before comparison

    return (url1 == url2)

def UpdateEserviceDatabase(enclaveclients, eservice_db_file):
    """ Update the eservice data base by adding new entires. The db is a json file. 
    Key is enclave id , value is eservice URL. The db contains the info for all enclaves known to the client.
    
    This method can also be used to create a new database by a client. 
    """
       
    if os.path.exists(eservice_db_file):
        try:
            with open(eservice_db_file, 'r') as fp:
                eservice_db = json.load(fp)
        except Exception as e:
            logger.error('Could not open encalve service database file : ' + str(e))
            sys.exit(-1)
    else :
        eservice_db = dict()
        
    num_curr_entires = len(eservice_db)
    
    for enclave in enclaveclients:

        try : 
            enclave_id = enclave.enclave_id
            url = enclave.ServiceURL
            if enclave_id in eservice_db.keys():
                # if the enclave is already in the database, if must be hosted at the same URL 
                if not are_the_urls_same(eservice_db[enclave_id], url):
                    logger.info(eservice_db[enclave_id])
                    logger.info(url)
                    logger.error('Enclave is hosted at a URL different from the one found in the database. Exiting ...')
                    sys.exit(-1)
            else :
                # make sure the url is not already present in the database. Each URL hosts atmost one enclave, and each enaclave is hosted by one URL
                if url in eservice_db.values():
                    logger.error('Multiple enclaves hosted at the same URL. Exiting ...')
                    sys.exit(-1)
                eservice_db[enclave_id] = url
        except Exception as e:
            logger.error('Unable to get enclave id for URLS in config: ' + str(e))
            sys.exit(-1)

    if len(eservice_db) > num_curr_entires:
        logger.info('Adding %d new entries to eservice data base', len(eservice_db) - num_curr_entires)
        try:
            with open(eservice_db_file, 'w') as fp:
                json.dump(eservice_db, fp)
        except Exception as e:
            logger.error('Could not update the encalve service database: ' + str(e))
            sys.exit(-1)
    else:
        logger.info('All enclaves already present in the eservice database. Nothing new to add')


## -----------------------------------------------------------------
## -----------------------------------------------------------------
def LocalMain(commands, config) :
    # ---------- load the contract ----------
    try :
        ledger_config = config['Sawtooth']
        contract_config = config['Contract']
        service_config = config['Service']
        key_config = config['Key']
    except KeyError as ke :
        logger.error('missing configuration section %s', str(ke))
        sys.exit(-1)

    # ---------- load the invoker's keys ----------
    try :
        keyfile = key_config['FileName']
        keypath = key_config['SearchPath']
        client_keys = ServiceKeys.read_from_file(keyfile, keypath)
    except KeyError as ke :
        logger.error('missing configuration parameter %s', str(ke))
        sys.exit(-1)
    except Exception as e :
        logger.error('unable to load client keys; %s', str(e))
        sys.exit(-1)

    # ---------- read the contract source code ----------
    try :
        contract_name = contract_config['Name']
        data_directory = contract_config['DataDirectory']
        save_file = contract_config['SaveFile']
        source_file = contract_config['SourceFile']
        source_path = contract_config['SourceSearchPath']
        contract_code = ContractCode.create_from_scheme_file(contract_name, source_file, source_path)
    except KeyError as ke :
        logger.error('missing configuration parameter %s', str(ke))
        sys.exit(-1)
    except Exception as e :
        logger.error('unable to load contract source; %s', str(e))
        sys.exit(-1)

    logger.info('Loaded contract data for %s', contract_name)

    # ---------- set up the enclave clients ----------

    try :
        enclaveclients = []
        for url in service_config['EnclaveServiceURLs'] :
            enclaveclients.append(EnclaveServiceClient(url))
    except Exception as e :
        logger.error('unable to setup enclave services; %s', str(e))
        sys.exit(-1)

    # Add enclaves' URLS to the eservice data base file if they dont already exit. 
    # The db is a json file. Key is enclave id , value is eservice URL. The db contains the info for all enclaves known to the client
    if config.get('eservice_db_json_file') is not None:
        eservice_db_file = config['eservice_db_json_file']
        try:
            UpdateEserviceDatabase(enclaveclients, eservice_db_file)
        except Exception as e:
            logger.error('Unable to update eservice database:' + str(e))
            sys.exit(-1)
        
    # ---------- set up the provisioning service clients ----------
    # This is a dictionary of provisioning service public key : client pairs
    try :
        provclients = []
        for url in service_config['ProvisioningServiceURLs'] :
            provclients.append(ProvisioningServiceClient(url))
    except Exception as e :
        logger.error('unable to setup provisioning services; %s', str(e))
        sys.exit(-1)

    logger.debug("All enclaveclients: %s", enclaveclients)
    logger.debug("All provclients: %s", provclients)

    # process the commands to create & register the contract
    if 'register' in commands :
        try :
            provisioning_service_keys = [pc.identity for pc in provclients]
            contract_id = register_contract(
                ledger_config, client_keys, contract_code, provisioning_service_keys)

            logger.info('Registered contract %s with id %s', contract_name, contract_id)
            contract_state = ContractState.create_new_state(contract_id)
            contract = Contract(contract_code, contract_state, contract_id, client_keys.identity)
            contract.save_to_file(save_file, data_dir=data_directory)
        except Exception as e :
            logger.error('failed to register the contract; %s', str(e))
            sys.exit(-1)
    else :
        # need to read the contract from the contract file
        contract = Contract.read_from_file(ledger_config, contract_name, data_directory)

    if 'addenclave' in commands :
        encrypted_state_encryption_keys = AddEnclaveSecrets(
            ledger_config, contract.contract_id, client_keys, enclaveclients, provclients)

        for enclave_id in encrypted_state_encryption_keys :
            encrypted_key = encrypted_state_encryption_keys[enclave_id]
            contract.set_state_encryption_key(enclave_id, encrypted_key)

        contract.save_to_file(save_file, data_dir=data_directory)
        logger.info('Successfully added enclave secrets to ledger for contract %s', contract_code.name)

    if 'create' in commands :
        CreateContract(ledger_config, client_keys, enclaveclients, contract)

        contract.contract_state.save_to_cache(data_dir = data_directory)
        contract.save_to_file(save_file, data_dir=data_directory)

    print('export CONTRACTID={0}'.format(contract.contract_id))

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
def Main(commands) :
    # parse out the configuration file first
    conffiles = [ 'pcontract.toml' ]
    confpaths = [ ".", "./etc", ContractEtc ]

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='configuration file', nargs = '+')

    parser.add_argument('--identity', help='Identity to use for the process', required = True, type = str)

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    parser.add_argument('--ledger', help='URL for the Sawtooth ledger', type=str)
    parser.add_argument('--contract', help='Name of the contract', required = True, type = str)
    parser.add_argument('--source', help='Gipsy Scheme source for the contract', required=True, type=str)
    parser.add_argument('--save-file', help='Name of the file where contract data is stored', type=str)

    parser.add_argument('--key-dir', help='Directories to search for key files', nargs='+')
    parser.add_argument('--data-dir', help='Path for storing generated files', type=str)
    parser.add_argument('--source-dir', help='Directories to search for contract source', nargs='+', type=str)

    parser.add_argument('--eservice-url', help='List of enclave service URLs to use', nargs='+')
    parser.add_argument('--pservice-url', help='List of provisioning service URLs to use', nargs='+')

    parser.add_argument('--enclaveservice-db', help='json file mapping enclave ids to correspodnign eservice URLS', type=str)

    options = parser.parse_args()

    # first process the options necessary to load the default configuration
    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    global config_map
    config_map['identity'] = options.identity
    config_map['contract'] = options.contract
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

    # process the reset of the command parameters

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
            'EnclaveServiceURLs' : [],
            'ProvisioningServiceURLs' : []
        }
    if options.eservice_url :
        config['Service']['EnclaveServiceURLs'] = options.eservice_url
    if options.pservice_url :
        config['Service']['ProvisioningServiceURLs'] = options.pservice_url

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
            'Name' : options.contract,
            'DataDirectory' : ContractData,
            'SaveFile' : options.contract + '.pdo',
            'SourceName' : options.contract,
            'SourceSearchPath' : [ ".", "./contract", os.path.join(ContractHome,'contracts') ]
        }

    config['Contract']['SourceName'] = options.source
    if options.save_file :
        config['Contract']['SaveFile'] = options.save_file
    if options.data_dir :
        config['Contract']['DataDirectory'] = options.data_dir
    if options.source_dir :
        config['Contract']['SourceSearchPath'] = options.source_dir

    if options.enclaveservice_db:
        config['eservice_db_json_file'] = options.enclaveservice_db

    putils.set_default_data_directory(config['Contract']['DataDirectory'])

    # GO!!!
    LocalMain(commands, config)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
def Register() :
    Main(['register'])

def Create() :
    Main(['register', 'addenclave', 'create'])

def AddEnclave() :
    Main(['addenclave'])
