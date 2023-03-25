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
import pdo.common.config as pconfig
from pdo.contract.response import ContractResponse
import pdo.common.block_store_manager as pblocks

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def LocalMain(config) :
    # if there is a script file, process it; the interactive
    # shell will start unless there is an explicit exit in the script
    script_file = config.get("ScriptFile")
    if script_file :
        shell = ContractController.CreateController(config, echo=False, interactive=False)

        logger.debug("Processing script file %s", str(script_file))
        exit_code = ContractController.ProcessScript(shell, script_file)
        sys.exit(exit_code)

    shell = ContractController.CreateController(config, echo=True, interactive=True)
    shell.cmdloop()
    print("")

    sys.exit(shell.exit_code)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

## -----------------------------------------------------------------
ContractHost = os.environ.get("PDO_HOSTNAME", "localhost")
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
ContractEtc = os.path.join(ContractHome, "etc")
ContractKeys = os.path.join(ContractHome, "keys")
ContractLogs = os.path.join(ContractHome, "logs")
ContractData = os.path.join(ContractHome, "data")
LedgerURL = os.environ.get("PDO_LEDGER_URL", "http://127.0.0.1:6600/")
ScriptBase = os.path.splitext(os.path.basename(sys.argv[0]))[0]
ContractInterpreter = os.environ.get("PDO_INTERPRETER", "gipsy")

config_map = {
    'base' : ScriptBase,
    'data' : ContractData,
    'etc'  : ContractEtc,
    'home' : ContractHome,
    'host' : ContractHost,
    'keys' : ContractKeys,
    'logs' : ContractLogs,
    'interpreter' : ContractInterpreter,
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

    parser = argparse.ArgumentParser(allow_abbrev=False)

    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='directories to search for the configuration file', nargs = '+')

    parser.add_argument('-i', '--identity', help='Identity to use for the process', type=str)

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    parser.add_argument('--ledger', help='URL for the ledger', type=str)

    parser.add_argument('--data-dir', help='Directory for storing generated files', type=str)
    parser.add_argument('--source-dir', help='Directories to search for contract source', nargs='+', type=str)
    parser.add_argument('--key-dir', help='Directories to search for key files', nargs='+')

    parser.add_argument('--eservice-db', help='json file for eservice database', type=str)

    parser.add_argument('-m', '--mapvar', help='Define variables for script use', nargs=2, action='append')

    options, script = parser.parse_known_args()

    # first process the options necessary to load the default configuration
    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    global config_map
    config_map['identity'] = '__unknown__'
    if options.identity :
        config_map['identity'] = options.identity
    if options.data_dir :
        config_map['data'] = options.data_dir
        ContractData = options.data_dir

    try :
        config = pconfig.parse_configuration_files(conffiles, confpaths, config_map)
    except pconfig.ConfigurationException as e :
        logger.error(str(e))
        sys.exit(-1)

    # set up the logging configuration
    if config.get('Logging') is None :
        config['Logging'] = {
            'LogFile' : '__screen__',
            'LogLevel' : 'WARN'
        }
    if options.logfile :
        config['Logging']['LogFile'] = options.logfile
    if options.loglevel :
        config['Logging']['LogLevel'] = options.loglevel.upper()

    plogger.setup_loggers(config.get('Logging', {}))

    # set up the ledger configuration
    if config.get('Ledger') is None :
        config['Ledger'] = {
            'LedgerURL' : 'http://localhost:6600',
        }
    if options.ledger :
        config['Ledger']['LedgerURL'] = options.ledger

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
            'EnclaveServiceDatabaseFile' : os.path.join(ContractData, 'eservice_db.json')
        }

    if options.eservice_db:
        config['Service']['EnclaveServiceDatabaseFile'] = options.eservice_db

    # set up the data paths
    if config.get('Contract') is None :
        config['Contract'] = {
            'DataDirectory' : ContractData,
            'BlockStore' : os.path.join(ContractData, "local_cache.mdb"),
            'SourceSearchPath' : [ ".", "./contract", os.path.join(ContractHome,'contracts') ]
        }

    if options.data_dir :
        config['Contract']['DataDirectory'] = options.data_dir
    if options.source_dir :
        config['Contract']['SourceSearchPath'] = options.source_dir

    if config['Contract'].get('BlockStore') is None :
        config['Contract']['BlockStore'] = os.path.join(config['Contract']['DataDirectory'], "local_cache.mdb"),

    # make the configuration available to all of the PDO modules
    pconfig.initialize_shared_configuration(config)

    if script :
        config["ScriptFile"] = script.pop(0)

        varmap = config.get("Bindings", {})
        while script :
            try :
                key = script.pop(0)
                val = script.pop(0)
            except ValueError :
                logger.error('unable to process script arguments')
                sys.exit(1)

            key = key.lstrip('-')
            varmap[key] = val
        config["Bindings"] = varmap

    # this sets the initial bindings available in the script
    if options.mapvar :
        varmap = config.get("Bindings", {})
        for (k, v) in options.mapvar : varmap[k] = v
        config["Bindings"] = varmap

    # GO!
    LocalMain(config)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
