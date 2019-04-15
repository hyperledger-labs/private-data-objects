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

import logging
logger = logging.getLogger(__name__)

from pdo.client.controller.contract_controller import ContractController
import pdo.common.utility as putils
import pdo.service_client.service_data.eservice as db

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def LocalMain(config) :
    shell = ContractController(config)

    # load the eservice database
    if  os.path.exists(config['Service']['EnclaveServiceDatabaseFile']):
        try:
            db.load_database(config['Service']['EnclaveServiceDatabaseFile'])
            logger.info('Loading the eservice database from json file %s', str(config['Service']['EnclaveServiceDatabaseFile']))
        except Exception as e:
            logger.error('Error loading eservice database %s', str(e))
            sys.exit(-1)
    
    # load the bindings specified in the configuration
    for (key, val) in config.get("VariableMap", {}).items() :
        shell.bindings.bind(key, val)

    # if there is a script file, process it; the interactive
    # shell will start unless there is an explicit exit in the script
    script_file = config.get("ScriptFile")
    if script_file :
        if not ContractController.ProcessScript(shell, script_file) :
            sys.exit(0)

    shell.cmdloop()
    print("")

    sys.exit(0)

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
    parser.add_argument('--config-dir', help='directories to search for the configuration file', nargs = '+')

    parser.add_argument('-i', '--identity', help='Identity to use for the process', type=str)
    parser.add_argument('-c', '--contract', help='Name of the contract', type = str)

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    parser.add_argument('--ledger', help='URL for the Sawtooth ledger', type=str)

    parser.add_argument('--data-dir', help='Directory for storing generated files', type=str)
    parser.add_argument('--source-dir', help='Directories to search for contract source', nargs='+', type=str)
    parser.add_argument('--key-dir', help='Directories to search for key files', nargs='+')

    parser.add_argument('--eservice-db', help='json file for eservice database', type=str)
    parser.add_argument('--eservice-name', help='List of enclave services to use. Give names as in database', nargs='+')
    parser.add_argument('--eservice-url', help='List of enclave service URLs to use', nargs='+')
    parser.add_argument('--pservice-url', help='List of provisioning service URLs to use', nargs='+')

    parser.add_argument('-m', '--mapvar', help='Define variables for script use', nargs=2, action='append')
    parser.add_argument('-s', '--script', help='File from which to read script', type=str)

    options = parser.parse_args()

    # first process the options necessary to load the default configuration
    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    global config_map
    config_map['identity'] = '__unknown__'
    if options.identity :
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
            'EnclaveServiceNames' : [],
            'EnclaveServiceURLs' : [],
            'ProvisioningServiceURLs' : [],
            'EnclaveServiceDatabaseFile' : None
        }

    if options.eservice_name:
        config['Service']['EnclaveServiceNames'] = options.eservice_name
    if options.eservice_db:
        config['Service']['EnclaveServiceDatabaseFile'] = options.eservice_db
    if options.eservice_url :
        config['Service']['EnclaveServiceURLs'] = options.eservice_url
        # we will not use database
        config['Service']['EnclaveServiceNames'] = []
    if options.pservice_url :
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

    if options.script :
        config["ScriptFile"] = options.script

    if options.mapvar :
        varmap = config.get("VariableMap", {})
        for (k, v) in options.mapvar : varmap[k] = v
        config["VariableMap"] = varmap

    # GO!
    LocalMain(config)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
