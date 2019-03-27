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

from pdo.service_client.servicedatabase import ServiceDB_Manager

import argparse


def LocalMain(commands, config) :

    if 'create' in commands :
        
        #make sure there is no json file already present
        if os.path.exists(config['Service']['EnclaveServiceDatabaseFile']):
            logger.error('Cannot create a new database with the chosen json filename. File already exists')
            sys.exit(-1)

        #make sure that there are names for each of the new eservice to add
        if len(config['Service']['EnclaveServiceNames']) < len(config['Service']['EnclaveServiceURLs']):
            logger.error('Please provide a name for each eservice to be added to the database')
            sys.exit(-1)

        #create an empty db
        db = ServiceDB_Manager(service_type='eservice')
        
        names = config['Service']['EnclaveServiceNames']
        urls = config['Service']['EnclaveServiceURLs']

        # add entries to db
        for index, url in enumerate(urls):
            try :
                client = db.get_serviceclient_by_url(url=url)
                db.add_new_info(name = names[index], url=url, id = client.enclave_id)
            except Exception as e:
                logger.error('Unable to create new database. Error adding new entry for url ' + str(url) + str(e))
                sys.exit(-1)
        
        # save as json file
        try:
            db.save_data_to_file(config['Service']['EnclaveServiceDatabaseFile'])
        except Exception as e:
            logger.error('Unable to create new database. Failed to save as json file' + str(e))
            sys.exit(-1)

        logger.info('Created a new database with ' + str(len(urls)) + ' entries.')

    else :
        # load the data from the json file for add/remove/update operation
        try:
            db = ServiceDB_Manager(service_type='eservice', file_name=config['Service']['EnclaveServiceDatabaseFile'])
        except Exception as e:
            logger.error('Unable to open existing eservice data file for the add/update/remove operation' + str(e))
            sys.exit(-1)

    if 'add' in commands :
        
        #make sure that there are names for each of the new eservice to add
        if len(config['Service']['EnclaveServiceNames']) < len(config['Service']['EnclaveServiceURLs']):
            logger.error('Please provide a name for each eservice to be added to the database')
            sys.exit(-1)

        names = config['Service']['EnclaveServiceNames']
        urls = config['Service']['EnclaveServiceURLs']

        # add entries to db
        for index, url in enumerate(urls):
            try :
                client = db.get_serviceclient_by_url(url=url)
                db.add_new_info(name = names[index], url=url, id = client.enclave_id)
            except Exception as e:
                logger.error('Error adding new entry for url ' + str(url) + str(e))
                sys.exit(-1)

        # save as json file
        try:
            db.save_data_to_file()
        except Exception as e:
            logger.error('Unable to add new entries: Failed to save as json file' + str(e))
            sys.exit(-1)
        
        logger.info('Added ' + str(len(urls)) + ' entries to the database')

    if 'update' in commands :
        # names are optional. However, if the name field is nonempty, must provide names for all urls.
        # if name is provided, will update the url of the entry corresponding name to input url, and also update the service_id
        # if only url is provided, will update the service_id

        num_updated = 0
        urls = config['Service']['EnclaveServiceURLs']
        names = []
        if config['Service'].get('EnclaveServiceNames'):
            names = config['Service']['EnclaveServiceNames']
            if len(config['Service']['EnclaveServiceNames']) < len(config['Service']['EnclaveServiceURLs']):
                logger.error('Please provide a name for each eservice to be updated to the database.')
                sys.exit(-1)
                
        for index, url in enumerate(urls):
            client = db.get_serviceclient_by_url(url=url)
            
            if len(names) > 0: # you are possibly changing the url for the name as well
                info_old = db.get_info(name = names[index])
                db.update_info(name = names[index], url = urls[index], id = client.enclave_id)
                info_new = db.get_info(name = names[index])
            else:
                info_old = db.get_info(url = url)
                db.update_info(name = info_old['name'], id = client.enclave_id) #url does not change
                info_new = db.get_info(name = info_old['name'])
                       
            num_updated += int(info_old != info_new)

        # save as json file
        try:
            db.save_data_to_file()
        except Exception as e:
            logger.error('Unable to update entries: Failed to save as json file' + str(e))
            sys.exit(-1)
        
        logger.info('Updated ' + str(num_updated) + ' entries in the database')

    if 'remove' in commands :
        # removes all entries corresponding to names and urls
        
        num_removed = 0 

        if config['Service'].get('EnclaveServiceNames'):
            names = config['Service']['EnclaveServiceNames']
            logger.info(names)
            for name in names:
                num_removed += db.remove_info(name = name)
        
        if config['Service'].get('EnclaveServiceURLs'):
            urls = config['Service']['EnclaveServiceURLs']
            logger.info(urls)
            for url in urls:
                num_removed +=  db.remove_info(url = url)

        # save as json file
        try:
            db.save_data_to_file()
        except Exception as e:
            logger.error('Unable to remove entries: Failed to save as json file' + str(e))
            sys.exit(-1)

        logger.info('Removed ' + str(num_removed) + ' entries from the database')



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
def Main(commands) :
    # parse out the configuration file first
    conffiles = [ 'pcontract.toml' ]
    confpaths = [ ".", "./etc", ContractEtc ]

    parser = argparse.ArgumentParser()
    
    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='configuration file', nargs = '+')

    parser.add_argument('--eservice-url', help='service urls',  nargs='+')
    parser.add_argument('--eservice-name', help='service names',  nargs='+')
    parser.add_argument('--eservice-db', help='json file for database', type=str)
    parser.add_argument('--loglevel', help='Set the logging level', default='INFO')
    parser.add_argument('--logfile', help='Name of the log file', default='__screen__')

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

    # process the reset of the command parameters

    # set up the service configuration
    if config.get('Service') is None :
        config['Service'] = {
            'EnclaveServiceURLs' : [],
            'EnclaveServiceNames' : [],
            'EnclaveServiceDatabaseFile' : None
        }

    if options.eservice_url :
        config['Service']['EnclaveServiceURLs'] = options.eservice_url
    
    if options.eservice_name :
        config['Service']['EnclaveServiceNames'] = options.eservice_name

    if options.eservice_db:
        config['Service']['EnclaveServiceDatabaseFile'] = options.eservice_db
    
   
    # GO!!!
    LocalMain(commands, config)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
def Add() :
    Main(['add'])

def Remove() :
    Main(['remove'])

def Create() :
    Main(['create'])

def Update():
    Main(['update'])    
