#!/usr/bin/env python

# Copyright 2019 Intel Corporation
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
#

import argparse
import hashlib
import os
import sys

import pdo.common.config as pconfig
import pdo.common.logger as plogger

import pdo.service_client.service_data.eservice as eservice_db

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def _hashed_identity_(enclave_id) :
    return hashlib.sha256(enclave_id.encode('utf8')).hexdigest()[:16]

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def _load_database_(config, create=False) :
    eservice_db.clear_all_data()
    database_file = config['Service']['EnclaveServiceDatabaseFile']

    if create and not os.path.exists(database_file) :
        _save_database_(config)

    loaded = False
    try :
        loaded = eservice_db.load_database(database_file, merge = False)
    except Exception as e :
        pass

    if not loaded :
        logger.error('unable to load eservice data from %s', database_file)
        sys.exit(-1)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def _save_database_(config) :
    database_file = config['Service']['EnclaveServiceDatabaseFile']
    try :
        eservice_db.save_database(database_file, overwrite=True)
    except Exception as e :
        logger.error('unable to save eservice data to %s; %s', database_file, str(e))
        sys.exit(-1)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def do_add_cmd(config, args) :
    """subcommand to add an entry to the eservice database
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help='enclave service url',  required=True)
    parser.add_argument('-n', '--name', help='name to give to this enclave service')

    options = parser.parse_args(args)

    _load_database_(config)

    try :
        ledger_config = config['Ledger']
        if not options.name :
            eservice_db.add_by_url(ledger_config, options.url)
        else :
            eservice_db.add_by_url(ledger_config, options.url, name=options.name)
    except Exception as e :
        logger.error('unable to add eservice data for %s; %s', options.url, str(e))
        sys.exit(-1)

    _save_database_(config)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def do_list_cmd(config, args) :
    """subcommand to list entries in the database
    """

    _load_database_(config)

    enclave_names = list(eservice_db.get_enclave_names())
    enclave_names.sort()

    for enclave_name in enclave_names :
        enclave_info = eservice_db.get_by_name(enclave_name)
        enclave_short_id = _hashed_identity_(enclave_info.enclave_id)
        print("{0:<18} {1:<18} {2}".format(enclave_name, enclave_short_id, enclave_info.url))

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def do_remove_cmd(config, args) :
    """subcommand to remove an entry from the database
    """
    parser = argparse.ArgumentParser(prog='remove', description='remove entry from the database')
    parser.add_argument('-n', '--name', help='name given to the enclave service', required=True)

    options = parser.parse_args(args)

    _load_database_(config)

    try :
        eservice_db.remove_by_name(options.name)
    except Exception as e :
        logger.error('unable to remove information for enclave %s; %s', options.name, str(e))
        sys.exit(-1)

    _save_database_(config)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def do_rename_cmd(config, args) :
    """subcommand to rename an entry in the database
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--old', help='current enclave name', type=str)
    parser.add_argument('-n', '--new', help='new enclave name', type=str)

    options = parser.parse_args(args)

    # load the database just to make sure the file exists
    _load_database_(config)
    if not eservice_db.rename_enclave(options.old, options.new) :
        print('failed to rename enclave')
        sys.exit(-1)

    _save_database_(config)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def do_reset_cmd(config, args) :
    """subcommand to clear all entries from the database
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--create', help='create a new database if necessary', action='store_true')

    options = parser.parse_args(args)

    # load the database just to make sure the file exists
    _load_database_(config, create=options.create)
    eservice_db.clear_all_data()
    _save_database_(config)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def do_verify_cmd(config, args) :
    """subcommand to verify an entry in the database
    """
    parser = argparse.ArgumentParser(prog='verify', description='verify current binding in the database')
    parser.add_argument('-n', '--name', help='name given to the enclave service', required=True)

    options = parser.parse_args(args)

    _load_database_(config)

    try :
        ledger_config = config['Ledger']
        enclave_info = eservice_db.get_by_name(options.name)
        if enclave_info is None :
            print('no enclave with name {0}'.format(options.name))
            sys.exit(-1)
        if not enclave_info.verify(ledger_config) :
            print('verification failed')
            sys.exit(-1)
    except Exception as e :
        logger.error('unable to verify eservice data for %s; %s', options.name, str(e))
        sys.exit(-1)

    print('verification succeeded')

# -----------------------------------------------------------------
# -----------------------------------------------------------------
ContractHost = os.environ.get("PDO_HOSTNAME", "localhost")
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
ContractEtc = os.path.join(ContractHome, "etc")
ContractKeys = os.path.join(ContractHome, "keys")
ContractLogs = os.path.join(ContractHome, "logs")
ContractData = os.path.join(ContractHome, "data")
LedgerURL = os.environ.get("PDO_LEDGER_URL", "http://127.0.0.1:6600/")
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
    dispatcher = {
        'add' :    do_add_cmd,
        'list' :   do_list_cmd,
        'remove' : do_remove_cmd,
        'rename' :  do_rename_cmd,
        'reset' :  do_reset_cmd,
        'verify' : do_verify_cmd,
    }

    # parse out the configuration file first
    conffiles = [ 'pcontract.toml' ]
    confpaths = [ ".", "./etc", ContractEtc ]

    parser = argparse.ArgumentParser()

    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='configuration file', nargs = '+')

    parser.add_argument('--loglevel', help='Set the logging level', default='INFO')
    parser.add_argument('--logfile', help='Name of the log file', default='__screen__')

    parser.add_argument('-l', '--ledger', help='Ledger URL', type=str)
    parser.add_argument('-d', '--database', help='json file for database', type=str)

    parser.add_argument('command', nargs=argparse.REMAINDER)

    options = parser.parse_args()

    # first process the options necessary to load the default configuration
    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    global config_map

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
    if config.get('Ledger') is None :
        config['Ledger'] = {
            'LedgerURL' : 'http://localhost:6600',
        }
    if options.ledger :
        config['Ledger']['LedgerURL'] = options.ledger

    #set up the service configuration
    if config.get('Service') is None :
        config['Service'] = {
            'EnclaveServiceDatabaseFile' : os.path.join(ContractData, "eservice-db.json")
        }

    if options.database:
            config['Service']['EnclaveServiceDatabaseFile'] = options.database

    if options.command :
        command = options.command.pop(0)
        command_function = dispatcher.get(command)
        if command_function is None :
            logger.error('unknown command %s', command)
            sys.exit(-1)

        command_function(config, options.command)
        sys.exit(0)

    logger.error('missing command')
    sys.exit(-1)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
