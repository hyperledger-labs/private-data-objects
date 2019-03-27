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
import logging
import sys
import os
import json

logger = logging.getLogger(__name__)

from pdo.service_client.enclave import EnclaveServiceClient
from pdo.common.utility import are_the_urls_same


__all__ = ['command_eservice']

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_eservice(state, bindings, pargs) :
    """controller command to manage the list of enclave services
    """
    subcommands = ['add', 'remove', 'set', 'use', 'info', 'list', 'udpatedb']

    parser = argparse.ArgumentParser(prog='eservice')
    subparsers = parser.add_subparsers(dest='command')
    add_parser = subparsers.add_parser('add')
    add_parser.add_argument('--url', help='URLs for the enclave service', type=str, nargs='+', required=True)

    remove_parser = subparsers.add_parser('remove')
    remove_parser.add_argument('--url', help='URLs for the enclave service', type=str, nargs='+', required=True)

    set_parser = subparsers.add_parser('set')
    set_parser.add_argument('--url', help='URLs for the enclave service', type=str, nargs='+', required=True)

    info_parser = subparsers.add_parser('use')
    info_parser.add_argument('--url', help='URLs for the enclave service', type=str, required=True)

    info_parser = subparsers.add_parser('info')
    info_parser.add_argument('--url', help='URLs for the enclave service', type=str, nargs='+')

    updatedb_parser = subparsers.add_parser('updatedb')
    updatedb_parser.add_argument('--enclaveservice-db', help='json file mapping enclave ids to correspodnign eservice URLS', type=str)


    list_parser = subparsers.add_parser('list')

    options = parser.parse_args(pargs)

    if options.command == 'updatedb' :
        if options.enclaveservice_db:
            state.set(['eservice_db_json_file'], options.enclaveservice_db)
        
        eservice_db_file = state.get(['eservice_db_json_file'])
        assert eservice_db_file is not None, 'Cannot update eservice database. No database file name specified.'
                
        service_urls = state.get(['Service', 'EnclaveServiceURLs'], [])
        
        try:
            UpdateEserviceDatabase(eservice_db_file, service_urls = service_urls)
        except Exception as e:
            logger.error('Unable to update the eservie database:' + str(e))
            sys.exit(-1)
        
        return

    if options.command == 'add' :
        services = set(state.get(['Service', 'EnclaveServiceURLs'], []))
        services = services.union(options.url)
        state.set(['Service', 'EnclaveServiceURLs'], list(services))
        return

    if options.command == 'remove' :
        services = set(state.get(['Service', 'EnclaveServiceURLs'], []))
        services = services.difference(options.url)
        state.set(['Service', 'EnclaveServiceURLs'], list(services))
        return

    if options.command == 'set' :
        state.set(['Service', 'EnclaveServiceURLs'], options.url)
        return

    if options.command == 'use' :
        state.set(['Service', 'PreferredEnclaveService'], options.url)
        return

    if options.command == 'info' :
        services = state.get(['Service', 'EnclaveServiceURLs'])
        if options.url :
            services = options.url

        for url in services :
            try :
                client = EnclaveServiceClient(url)
                print("{0} --> {1}".format(url, client.verifying_key))
            except :
                print('unable to retreive information from {0}'.format(url))
        return

    if options.command == 'list' :
        services = set(state.get(['Service', 'EnclaveServiceURLs'], []))
        for service in services :
            print(service)

        return

    raise Exception('unknown subcommand')

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def get_enclave_service(state=None, enclave_url=None) :
    """create an enclave client for the preferred enclave service; assumes
    exception handling by the calling procedure
    """
    if enclave_url is None :
        enclave_url = state.get(['Service', 'PreferredEnclaveService'], None)
        if enclave_url is None :
            enclave_url = random.choice(state.get(['Service', 'EnclaveServiceURLs'], []))

    if enclave_url is None :
        raise Exception('no enclave service specified')

    return EnclaveServiceClient(enclave_url)

def ReadEserviceDatabase(eservice_db_file):
    """ Read the eservice data base. The db is a json file. 
    Key is enclave id , value is eservice URL. The db contains the info for all enclaves known to the client.
    Return the database as a dictonary. 
    """

    if os.path.exists(eservice_db_file):
        try:
            with open(eservice_db_file, 'r') as fp:
                eservice_db = json.load(fp)
        except Exception as e:
            logger.error('Could not open encalve service database file : ' + str(e))
            sys.exit(-1)
    else:
        logger.error('Attempting to read non existent eservice data base file.')
        sys.exit(-1)
    
    return eservice_db

def UpdateEserviceDatabase(eservice_db_file, service_urls=None, service_clients=None):
    """ Update the eservice data base by adding new entires. The db is a json file. 
    Key is enclave id , value is eservice URL. The db contains the info for all enclaves known to the client.
    
    This method can also be used to create a new database by a client. If service_clients list is passed as input, both enclave_id and eservice_url
    will be obtained from this. Else, need to pass service_url list. In this case, enclave_id will be obtained by querying the url for public info
    """
    
    #read the current db   
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
    
    # get enclave_ids:
    enclave_ids = []
    if service_clients is not None:
        service_urls = []
        try:
            for client in service_clients:
                enclave_ids.append(client.enclave_id)
                service_urls.append(client.ServiceURL)
        except Exception as e:
            logger.error("Unable to get service url and id from the service client object" + str(e))
            sys.exit(-1)
    elif service_urls is not None:
        try:
            for url in service_urls:
                client = get_enclave_service(enclave_url=url)
                enclave_ids.append(client.enclave_id)
        except Exception as e:
            logger.error("Unable to query eservice url " + str(url) + " and get serivce id info: " + str(e))
    else:
        logger.error("Must provide either eservice_urls or eservice_clients as input to update the eservice database")
        sys.exit(-1)

    
    #update the db
    for index in range(len(enclave_ids)):
        enclave_id = enclave_ids[index]
        url = service_urls[index]
        
        if enclave_id in eservice_db.keys():
            # if the enclave is already in the database, if must be hosted at the same URL 
            if not are_the_urls_same(eservice_db[enclave_id], url):
                logger.info(eservice_db[enclave_id])
                logger.info(url)
                logger.error('Enclave is hosted at a URL different from the one found in the database. Exiting ...')
                sys.exit(-1)
        else :
            # before adding the enclave_id, make sure the url is not already present in the database. Each URL hosts atmost one enclave_id
            if url in eservice_db.values():
                logger.error('Multiple enclave_ids hosted at the same URL. Exiting ...')
                sys.exit(-1)
            # all good, collect the new entry to be added to db
            eservice_db[enclave_id] = url
    
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
