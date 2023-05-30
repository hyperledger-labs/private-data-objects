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

import pdo.common.config as pconfig
import pdo.common.logger as plogger
import pdo.common.utility as putils

from pdo.client.controller.contract_controller import State, Bindings
from pdo.client.controller.commands import *
import pdo.client.controller.commands

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def LocalMain(config, params) :
    try :
        identity = config['Client']['Identity']
        private_key_file = config['Key']['FileName']
    except :
        raise Exception('missing required configuration parameters')

    state = State(config, identity=identity, private_key_file=private_key_file)
    bindings = Bindings(config.get('Bindings', {}))

    # we are going to retrieve the command family name from the
    # name of the script; the standard mapping starts with 'pdo-'
    # which will be removed. then all of the '-' (which make nice
    # looking commands for bash) are replaced with '_' (which make
    # nice looking python function names)
    base_name = os.path.basename(sys.argv[0])
    command_name = base_name[len('pdo-'):] if base_name.startswith('pdo-') else base_name
    command_name = command_name.replace('-','_')

    command = getattr(pdo.client.controller.commands, command_name)
    command(state, bindings, params)

    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def Main() :
    config_map = pconfig.build_configuration_map()
    config_map['base'] = os.path.splitext(os.path.basename(sys.argv[0]))[0]

    # parse out the configuration file first
    conffiles = [ 'pcontract.toml' ]
    confpaths = [ ".", "./etc", config_map['etc'] ]

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

    parser.add_argument('--service-db', help='json file for eservice database', type=str)

    options, command_params = parser.parse_known_args()

    # first process the options necessary to load the default configuration
    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

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

    # set up the client config
    if config.get('Client') is None :
        config['Client'] = {
            'Identity' : config_map['identity'],
            'SearchPath' : confpaths,
        }
    if options.config_dir :
        config['Client']['SearchPath'] = confpaths

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
            'ServiceDatabaseFile' : os.path.join(ContractData, 'service_db.mdb')
        }

    if options.service_db:
        config['Service']['ServiceDatabaseFile'] = options.service_db

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

    LocalMain(config, command_params)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
