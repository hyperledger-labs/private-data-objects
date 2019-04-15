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
 
import os
import sys

import argparse
import logging
logger = logging.getLogger(__name__)

import pdo.common.config as pconfig
import pdo.common.logger as plogger

import pdo.service_client.service_data.eservice as db

import argparse

def Add_entries(config):
    """ Add entries to database. Return number of entries added"""

    ledger_config = config['Sawtooth']

    #make sure that there are names for each of the new eservice to add
    if len(config['Service']['EnclaveServiceNames']) < len(config['Service']['EnclaveServiceURLs']):
        logger.error('Please provide a name for each eservice to be added to the database')
        sys.exit(-1)

    names = config['Service']['EnclaveServiceNames']
    urls = config['Service']['EnclaveServiceURLs']

     # add entries to db
    for index, url in enumerate(urls):
        try :
            if db.add_info_to_database(names[index], url, ledger_config) is False:
                logger.error('Error adding new entry for url %s', str(url))
                sys.exit(-1)
        except Exception as e:
            logger.error('Error adding new entry for url %s: %s', str(url), str(e))
            sys.exit(-1)
    
    # save as json file
    try:
        db.save_database(config['Service']['EnclaveServiceDatabaseFile'], overwrite = True)
    except Exception as e:
        logger.error('Unable to create new database. Failed to save as json file : %s ', str(e))
        sys.exit(-1)
    
    num_entries_added = len(urls)
    return num_entries_added


def LocalMain(command, config) :

    if command=='create' :
        
        #create an empty db
        db.clear_all_data()
        num_entries_added= Add_entries(config)
        logger.info('Created a new database with  %d entries.',  num_entries_added)

    elif command ==  'add':
        
        # load the db to which you want to add to, reload & merge does not hurt
        db.load_database(config['Service']['EnclaveServiceDatabaseFile'], merge = True)
        num_entries_added= Add_entries(config)
        logger.info('Added %d entries to the database', num_entries_added)

    elif command =='update':
        # names are optional. However, if the name field is nonempty, must provide names for all urls.
        # if name is provided, will update the url of the entry corresponding name to input url, and also update the service_id
        # if only url is provided, will update the service_id

        
        # load the db from which you want to update
        db.load_database(config['Service']['EnclaveServiceDatabaseFile'], merge = True)
        
        ledger_config = config['Sawtooth']
        num_updated = 0
        urls = config['Service']['EnclaveServiceURLs']
        names = []

        if config['Service'].get('EnclaveServiceNames'):
            names = config['Service']['EnclaveServiceNames']
            if len(config['Service']['EnclaveServiceNames']) < len(config['Service']['EnclaveServiceURLs']):
                logger.error('Please provide a name for each eservice to be updated to the database.')
                sys.exit(-1)
                
        for index, url in enumerate(urls):
                        
            if len(names) > 0: # you are possibly changing the url for the name as well
                info_old = db.get_info_by_name(names[index])
                if not db.update_info_in_database(names[index], url, ledger_config):
                    logger.error('Failed to update info for name %s and url %s', str(names[index]), str(url) ) 
                    sys.exit(-1)
                info_new = db.get_info_by_name(names[index])
            else:
                info_old = db.get_info_by_url(url)
                if not db.update_info_in_database(info_old['name'], url, ledger_config):
                    logger.error('Failed to update info for url %s', str(url) ) 
                    sys.exit(-1)
                info_new = db.get_info_by_name(name = info_old['name'])
                       
            num_updated += int(info_old != info_new)

        # save as json file
        try:
            db.save_database(config['Service']['EnclaveServiceDatabaseFile'], overwrite = True)
        except Exception as e:
            logger.error('Unable to update entries: Failed to save as json file %s', str(e))
            sys.exit(-1)
        
        logger.info('Updated %d entries in the database', num_updated)
    
    elif command=='remove':
        # removes all entries corresponding to names and urls
        
        # load the db from which you want to remove
        db.load_database(config['Service']['EnclaveServiceDatabaseFile'], merge = True)
        
        num_removed = 0 

        if config['Service'].get('EnclaveServiceNames'):
            names = config['Service']['EnclaveServiceNames']
            for name in names:
                num_removed += db.remove_info_from_database(name = name)
        
        if config['Service'].get('EnclaveServiceURLs'):
            urls = config['Service']['EnclaveServiceURLs']
            for url in urls:
                num_removed +=  db.remove_info_from_database(url = url)

        # save as json file
        try:
            db.save_database(config['Service']['EnclaveServiceDatabaseFile'], overwrite = True)
        except Exception as e:
            logger.error('Unable to Remove entries: Failed to save as json file %s', str(e))
            sys.exit(-1)

        logger.info('Removed %d  entries from the database', num_removed)
    
    else:
        logger.error('Unsupported database command')
        sys.exit(-1)
    
    sys.exit(0)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## DO NOT MODIFY BELOW THIS LINE
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

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
    # parse out the configuration file first
    conffiles = [ 'pcontract.toml' ]
    confpaths = [ ".", "./etc", ContractEtc ]

    subcommands = ['add', 'remove', 'create', 'update']

    parser = argparse.ArgumentParser()
    
    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='configuration file', nargs = '+')
    parser.add_argument('--loglevel', help='Set the logging level', default='INFO')
    parser.add_argument('--logfile', help='Name of the log file', default='__screen__')
    parser.add_argument('--ledger', help='Ledger URL', type=str)

    subparsers = parser.add_subparsers(dest='command')
    
    create_parser = subparsers.add_parser('create')
    create_parser.add_argument('--eservice-url', help='service urls',  nargs='+')
    create_parser.add_argument('--eservice-name', help='service names',  nargs='+')
    create_parser.add_argument('--eservice-db', help='json file for database', type=str)
    
    add_parser = subparsers.add_parser('add')
    add_parser.add_argument('--eservice-url', help='service urls',  required=True, nargs='+')
    add_parser.add_argument('--eservice-name', help='service names', required=True,  nargs='+')
    add_parser.add_argument('--eservice-db', help='json file for database', type=str)

    remove_parser = subparsers.add_parser('remove')
    remove_parser.add_argument('--eservice-url', help='service urls',  nargs='+')
    remove_parser.add_argument('--eservice-name', help='service names', nargs='+')
    remove_parser.add_argument('--eservice-db', help='json file for database', type=str)

    update_parser = subparsers.add_parser('update')
    update_parser.add_argument('--eservice-url', help='service urls', required=True, nargs='+')
    update_parser.add_argument('--eservice-name', help='service names', nargs='+')
    update_parser.add_argument('--eservice-db', help='json file for database', type=str)

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
    if config.get('Sawtooth') is None :
        config['Sawtooth'] = {
            'LedgerURL' : 'http://localhost:8008',
        }
    if options.ledger :
        config['Sawtooth']['LedgerURL'] = options.ledger

    #set up the service configuration
    if config.get('Service') is None :
        config['Service'] = {
            'EnclaveServiceURLs' : [],
            'EnclaveServiceNames' : [],
            'EnclaveServiceDatabaseFile' : None
        }

    if options.eservice_db:
            config['Service']['EnclaveServiceDatabaseFile'] = options.eservice_db

    # process the commands to identify the urls and names
    if options.command == 'create':
        # for create, we will use urls and names from toml if not provided via cmd line options

        if options.eservice_url :
            config['Service']['EnclaveServiceURLs'] = options.eservice_url
        if options.eservice_name :
            config['Service']['EnclaveServiceNames'] = options.eservice_name
        
        LocalMain('create', config)
        return 

    if options.command == 'add':
        # for add we will use urls and names only from cmd line. 

        config['Service']['EnclaveServiceURLs'] = options.eservice_url
        config['Service']['EnclaveServiceNames'] = options.eservice_name
        
        LocalMain('add', config)
        return 

    if options.command == 'remove' :
        # for remove, we will use urls and names only from cmd line. But unlike add, one need not necessarily provide both urls and names

        config['Service']['EnclaveServiceURLs'] = []
        config['Service']['EnclaveServiceNames'] = []

        if options.eservice_url :
            config['Service']['EnclaveServiceURLs'] = options.eservice_url
        if options.eservice_name :
            config['Service']['EnclaveServiceNames'] = options.eservice_name
        
        LocalMain('remove', config)
        return 

    if options.command == 'update' :
        # for udpate also, we will use urls and names only from cmd line. This time, one gives either both urls and names, or just urls.

        config['Service']['EnclaveServiceNames'] = []

        config['Service']['EnclaveServiceURLs'] = options.eservice_url
        if options.eservice_name :
            config['Service']['EnclaveServiceNames'] = options.eservice_name

        LocalMain('update', config)
        return 
 
## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()