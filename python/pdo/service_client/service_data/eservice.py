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

import os
import sys
import json
import copy
import shutil
import datetime

import logging
logger = logging.getLogger(__name__)

from sawtooth.helpers.pdo_connect import PdoClientConnectHelper
from sawtooth.helpers.pdo_connect import ClientConnectException
from pdo.service_client.enclave import EnclaveServiceClient
from pdo.common.utility import are_the_urls_same
import pdo.common.keys as keys

# primary
__data__ = dict()
# dervived 
__url_by_name__ = dict()
__id_by_name__ = dict()
__name_by_url__ = dict()
__name_by_id__ = dict()


def clear_all_data():
    """ clear all dictonaries. Useful to create a fresh database."""
   
    global __data__

    __data__ = dict()
    update_dictionaries(__data__, merge=False)

def load_database(filename, merge = True):
    
    global __data__
    
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as fp:
                new_data = json.load(fp)
        except Exception as e:
            logger.exception('Failed to load json file for service database: %s', str(e))
            raise Exception from e
    else:
        raise Exception('Cannot load service database: File does not exist')

    if not isinstance(new_data, dict) or not are_entries_unique(new_data.values()):
        raise Exception('Cannot load database: File %s corresponds to an invalid database', str(filename))
                
    if merge:
        # if there are  common names, check that the corresponding infos are the same, else raise conflict during merge
        names_curr = set(__data__.keys())
        common_names = names_curr.intersection(set(new_data.keys()))
        for name in common_names:
            if not is_info_same(__data__[name], new_data[name]):
                raise Exception('Cannot load database: Conflict during merge')
            
        # do a temp merge and ensure that no two names contain the same id or url
        temp_merged_data = copy.deepcopy(__data__)
        temp_merged_data.update(new_data)
        if not are_entries_unique(temp_merged_data.values()):
            raise Exception('Cannot load database: Conflicts during merge')
        
        # all good, merge
        __data__.update(new_data)
    else:
        __data__ = dict()
        __data__.update(new_data)

    # update the derived data structures
    update_dictionaries(new_data, merge)

#--------------------------------------------
#--------------------------------------------

def save_database(filename, overwrite = False):
    """ Save the dictionary as a json file. If no new_file_name is provided, the json file used for init will be overwritten"""
    
    if os.path.exists(filename) and overwrite is False:
        raise Exception('Cannot save database to file. File already present')
    
    # dump json to temporary file, if write succeeds move to desired file
    temp_filename = filename + '_temp'
    try:
        with open(temp_filename, 'w') as fp:
            json.dump(__data__, fp)
        shutil.copyfile(temp_filename, filename)
    except Exception as e:
        raise Exception('Failed to save service database info as a json file: %s', str(e))
    
    try:
        os.remove(temp_filename)
    except Exception as e:
        logger.exception('failed to remove the temporary file, continuing with the execution however...')
    
#--------------------------------------------
#--------------------------------------------

def add_info_to_database(name,  url, ledger_config):
    """ Name, url and ledger_config are mandatory, id is automatically found fom the eservice. 
    Return True if add succeeds, else return False"""
    
    global __data__
    
    try :
        client = get_client_by_url(url)
    except Exception as e :
        logger.info('Cannot add info to database: %s', str(e))
        return False
    
    id = client.enclave_id

    #make sure that the new entry does not conflict with an existing entry
    if (get_info_by_name(name) is not None) or (get_info_by_url(url) is not None) or (get_info_by_id(id) is not None):
        logger.info('Cannot add info to database: new entry conflicts with existing database')
        return False
    
    #verify that the enclave has been registered with the ledger 
    try:
        is_info_valid, time_of_verification = verify_info(url, ledger_config, id, txn_keys = None, client = client)
        if is_info_valid:
            logger.info('Adding a new entry to eservice database')
            __data__[name] = {'url': url, 'id': id, 'last_verified_time': time_of_verification}
        else:
            logger.info('Cannot add info to database: Verification with ledger failed')
            return False
    except Exception as e:
        logger.info('Cannot add info to database: Unknown error while verifying with ledger: %s', str(e))
        return False

    update_dictionaries({name:__data__[name]}, merge = True)
    return True

#--------------------------------------------
#--------------------------------------------

def update_info_in_database(name, url, ledger_config):
    """ Update the entry corresponding to name. Replace url with incoming url. 
    Return True if udpate succeeds, else retrun False. If no entry with name is found, 
    return False"""

    
    global __data__

    if not __data__.get(name):
        return False

    try :
        client = get_client_by_url(url)
    except Exception as e :
        logger.info('Cannot update info in database: %s', str(e))
        return False
    
    id = client.enclave_id

    #make sure that the update info does not conflict with an existing entry. if url is already present, it must be against the same name
    info_by_url = get_info_by_url(url)
    if info_by_url is not None:
        if info_by_url['name'] != name:
            logger.info('Cannot update info in database: new info conflicts with existing database')
            return False    
    
    # if the id is present, it must be against the same name (if so there is nothing to update)
    info_by_id = get_info_by_id(id)
    if info_by_id is not None:
        if info_by_id['name'] == name:
            logger.info('Nothing to update. url and id for name have not changed')
            return True
        else:
            logger.info('Cannot update info in database: new info conflicts with existing database')
            return False
    
    # Ok, we now have a new id, first verify that the id has been registered with the ledger 
    try:
        is_info_valid, time_of_verification = verify_info(url, ledger_config, id, txn_keys = None, client = client)
        if is_info_valid:
            logger.info('Updating entry corresponding to %s in eservice database', str(name))
            __data__[name] = {'url': url, 'id': id, 'last_verified_time': time_of_verification}
        else:
            logger.info('Cannot update info in database: Verification with ledger failed')
            return False
    except Exception as e:
        logger.info('Cannot update info in database: Unknown error while verifying with ledger: %s', str(e))
        return False

    update_dictionaries({name:__data__[name]}, merge = True)
    return True
#--------------------------------------------
#--------------------------------------------

def remove_info_from_database(name = None, id = None, url = None):
    """ Remove entries corresponding to name & id & url. Return the number of entries removed"""

    def remove(info):
        global __url_by_name__
        global __id_by_name__
        global __name_by_url__
        global __name_by_id__
        global __data__
        
        __data__.pop(info['name'])
        __id_by_name__.pop(info['name'])
        __url_by_name__.pop(info['name'])
        __name_by_id__.pop(info['id'])
        __name_by_url__.pop(info['url'])

    num_removed = 0

    # remove by name
    info = get_info_by_name(name)
    if info is not None:
        remove(info)
        num_removed+=1
        
    # remove by id
    info = get_info_by_id(id)
    if info is not None:
        remove(info)
        num_removed+=1

    # remove by url
    info = get_info_by_url(url)
    if info is not None:
        remove(info)
        num_removed+=1

    logger.info('Removed %d entries from the database', num_removed)
    return num_removed

#--------------------------------------------
#--------------------------------------------

def get_info_by_name(name):
    """ Get service info as present in database using name. Returns a dictonary with four fields:
    name, id, url, last_verified_time. Return None if there is no matching entry. """

    if __data__.get(name):
        info = copy.deepcopy(__data__[name])
        info['name'] = name
        return info
    else:
        return None

#--------------------------------------------
#--------------------------------------------
    
def get_info_by_id(id):
    """ Get service info as present in database using id. Returns a dictonary with four fields:
    name, id, url, last_verified_time. Return None if there is no matching entry. """

    if __name_by_id__.get(id):
        name = __name_by_id__[id]
        info = copy.deepcopy(__data__[name])
        info['name'] = name
        return info
    else:
        return None

#--------------------------------------------
#--------------------------------------------

def get_info_by_url(url):
    """ Get service info as present in database using url. Returns a dictonary with four fields:
    name, id, url, last_verified_time. Return None if there is no matching entry. """
    
    for url_in_db in __name_by_url__.keys():
        if are_the_urls_same(url_in_db, url):
            name = __name_by_url__[url_in_db]
            info = copy.deepcopy(__data__[name])
            info['name'] = name
            return info
    
    return None

#--------------------------------------------
#--------------------------------------------

def get_client_by_name(name):
    """ get client for eservice identified by name"""

    try:
        return get_client_by_url(__url_by_name__[name])
    except Exception as e:
        raise Exception('Cannot generate client for eservice %s: %s', str(name), str(e))

#--------------------------------------------
#--------------------------------------------

def get_client_by_url(url):
    """ get client for eservice@url"""

    try :
        return EnclaveServiceClient(url)
    except Exception as e :
        raise Exception('Cannot generate client for eservice at %s: %s', str(url), str(e))
        

#--------------------------------------------
#--------------------------------------------

def get_client_by_id(id):
    """ get client for eservice identified by id"""

    try:
        return get_client_by_url(__url_by_name__[__name_by_id__[id]])
    except Exception as e:
        raise Exception('Cannot generate client for eservice id %s: %s', str(id), str(e))

#--------------------------------------------
#--------------------------------------------

def verify_info(url, ledger_config, id, txn_keys = None, client = None):
    """Verify two things: 1. Check that the eservice@url hosts the id. This check is performed only if client is None. 
    2. Verify that id is registered with DL. Return the pair (True/Falase, verification_time).  verification_time is None for false verifcation"""
    
    if client is None:
        try :
            client = EnclaveServiceClient(url)
        except Exception as e :
            raise Exception('failed to contact enclave service; %s', str(e))

        # match id with eservice id
        if id != client.enclave_id: 
            logger.info('Failed to verify enclave. Database info does match with info from eservice')
            return (False, None)
    
    # check againt ledger info
    try:
        if txn_keys is None:
            txn_keys = keys.TransactionKeys()
        sawtooth_client = PdoClientConnectHelper(ledger_config['LedgerURL'], key_str = txn_keys.txn_private)
        enclave_state = sawtooth_client.get_enclave_dict(client.enclave_id)
    except ClientConnectException as ce :
        logger.info('failed to verify enclave registration with the ledger; %s', str(ce))
        return (False, None)
    except:
        raise Exception('unknown error occurred while verifying enclave registration with ledger')
    
    return (True, str(datetime.datetime.now()))
    
#--------------------------------------------
#--------------------------------------------
def is_info_same(info1, info2):
    """ Check is both infos are the same. Return True/False """

    return (info1['id'] == info2['id']) and (info1['last_verified_time'] == info2['last_verified_time']) and are_the_urls_same(info1['url'], info2['url'])


def are_entries_unique(infos):
    """ Check if all urls and ids are distinct in the infos. Return True/False"""

    urls = set()
    ids = set()
    
    for info in infos:
        
        add_url = True
        for url in urls:
            if are_the_urls_same(url, info['url']):
                add_url = False
                break
        if add_url:
            urls.add(info['url'])

        ids.add(info['id'])

    return 2*len(infos) == len(urls) + len(ids)

#--------------------------------------------
#--------------------------------------------

def update_dictionaries(new_data, merge = True):
    """ Update the derived dictonaries."""
    
    global __url_by_name__
    global __id_by_name__
    global __name_by_url__
    global __name_by_id__
    
    if merge is False:
        __url_by_name__ = dict()
        __id_by_name__ = dict()
        __name_by_url__ = dict()
        __name_by_id__ = dict()

    for name, info in new_data.items():
        __url_by_name__[name] = info['url']
        __id_by_name__[name] = info['id']
        __name_by_url__[info['url']] = name
        __name_by_id__[info['id']] = name

