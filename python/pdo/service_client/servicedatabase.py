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
import json
import copy

import logging
logger = logging.getLogger(__name__)

from pdo.service_client.enclave import EnclaveServiceClient
from pdo.service_client.storage import StorageServiceClient
from pdo.common.utility import are_the_urls_same


class ServiceDB_Manager():
    """ A class to wrap calls to service database manager. 
    
    The data is saved as a json file, and is loaded as a dictionary of (key, value) pairs.  Key is a client chosen short name for the service.
    Value is a dictionary with entries corresponding to id (if service is eservice), url, verifying_key (if service is sservice).  
    
    It is also possible to first create an empty dictonary, add entries and then save as a json file.
    
    Name, id (enclave_id) and url are all synonyms for a given eservice. Exceptions will be raised if there are violations. To fix a broken database, 
    use the remove_service method to remove multiple or replicated entries for a given identifier from the database. After remove, use the add_new_entry
    to add a unique entry for a given identifier"""

    def __init__(self, file_name = None, service_type='eservice'):

        if file_name is not None:
            self.file_name = file_name
            try:
                self.load_data_from_file()
            except Exception as e:
                logger.exception('Failed to load database during initialization' + str(e))
                raise Exception from e
        else:
            self.data = dict()

        self._service_type = service_type
        
        if (self._service_type is not 'eservice') and (self._service_type is not 'sservice'):
            logger.exception('Cannot initialize service database manager: service_type must be eservice or sservice')
            raise Exception('Cannot initialize service database manager: service_type must be eservice or sservice')


    #--------------------------------------------
    #--------------------------------------------

    @staticmethod
    def get_eservice_client(url):
        try :
            client = EnclaveServiceClient(url)
        except Exception as e :
            logger.exception('failed to contact enclave service; %s', str(e))
            raise Exception from e
        return client

    #--------------------------------------------
    #--------------------------------------------

    @staticmethod
    def get_sservice_client(url):
        try :
            client = StorageServiceClient(url)
        except Exception as e :
            logger.exception('failed to contact storage service; %s', str(e))
            raise Exception from e
        return client

    def load_data_from_file(self):
        """ Load the json data file as a dictionary"""

        if os.path.exists(self.file_name):
            try:
                with open(self.file_name, 'r') as fp:
                    self.data = json.load(fp)
                    if not isinstance(self.data, dict):
                        raise Exception('Invalid json file for service database: Json file must be loadable as python dictionary')
            except Exception as e:
                logger.exception('Failed to load json file for service database: ' + str(e))
                raise Exception from e
        else:
            raise Exception('Cannot load service database: Data file does not exist')
    
    #--------------------------------------------
    #--------------------------------------------
    
    def save_data_to_file(self, new_file_name = None):
        """ Save the dictionary as a json file. If no new_file_name is provided, the json file used for init will be overwritten"""
        if new_file_name is not None:
            self.file_name = new_file_name

        if self.file_name is None:
            logger.exception('Cannot save service database info without providing json file name')
            raise Exception('Cannot save service database info without providing json file name')
        
        try:
            with open(self.file_name, 'w') as fp:
                json.dump(self.data, fp)
        except Exception as e:
            logger.exception('Failed to save service database info as a json file: ' + str(e))
            raise Exception('Failed to save service database info as a json file: ' + str(e))


    #--------------------------------------------
    #--------------------------------------------
    
    def get_serviceclient_by_name(self, name):
        """ Return the service client idenfied by its name"""

        service_info = self.data[name]
        if service_info['url'] is None:
            logger.exception('Unable to find service url in datatabase for ' + str(name) + '. Cannot create serivce client without the url')
            raise Exception('Unable to find service url in datatabase for ' + str(name) + '. Cannot create serivce client without the url')
        
        if self._service_type=='eservice':
            client = self.get_eservice_client(service_info['url'])
            if service_info.get('id'):
                if service_info['id'] != client.enclave_id:
                    logger.exception('Enclave hosted by the eservice does not match the one found in database: Cannot create service client')
                    raise Exception('Enclave hosted by the eservice does not match the one found in database: Cannot create service client')
        else:
            client = self.get_sservice_client(service_info['url'])
        
        return client
    #--------------------------------------------
    #--------------------------------------------
    
    def get_serviceclient_by_url(self, url):
        """ Return the service client for the service located at url. """

        if self._service_type=='eservice':
            return self.get_eservice_client(url)
        else:
            return self.get_sservice_client(url)
        
    #--------------------------------------------
    #--------------------------------------------
    
    def get_serviceclient_by_id(self, id):
        """ Return the service client identified by its id. An exception will be raised if the id is found multiple times in the database"""

        entries = list(filter(lambda entry: entry['id']==id , self.data.values()))
        
        if len(entries) == 0:
            logger.exception('Cannot create service client : id not found in database')
            raise Exception('Cannot create service client : id not found in database')
        elif len(entries) > 1:
            logger.exception('Cannot create service client : Invalid Database, id found multiple times in the database')
            raise Exception('Cannot create service client : Invalid Database, id found multiple times in the database')
        elif entries[0]['url'] is None:
            logger.exception('Unable to find service url for given id. Cannot create serivce client without the url')
            raise Exception('Unable to find service url for given id. Cannot create serivce client without the url')

        
        if self._service_type=='eservice':
            client =  self.get_eservice_client(entries[0]['url'])
            service_info = self.get_info(url = entries[0]['url'])
            if service_info['id'] != id:
                logger.exception('Enclave hosted by the eservice does not match the one found in database: Cannot create service client')
                raise Exception('Enclave hosted by the eservice does not match the one found in database: Cannot create service client')
        else:
            logger.exception('Unsupported operation. Service client by id is supported only for eservice and not for sservice')
            raise Exception('Unsupported operation. Service client by id is supported only for eservice and not for sservice')

        return client
    
    #--------------------------------------------
    #--------------------------------------------
    
    def add_new_info(self, name, id = None, url = None):
        """ Add a new entry to the data base. If any one field of the new entry is already in the database, an exception will be raised."""

        if name is None:
            logger.exception('Cannot add entry to service database: Need a name for the entry')
            raise Exception('Cannot add entry to service database: Need a name for the entry')
        elif name in self.data.keys():
            logger.exception('Cannot add entry to service database: Name already present, give a new name for the entry')
            raise Exception('Cannot add entry to service database: Name already present, give a new name for the entry')
        
        if url is not None:
            entries = list(filter(lambda entry: are_the_urls_same(entry['url'], url) , self.data.values()))
            if len(entries) >0:
                logger.exception('Cannot add entry to service database : url already present in the database')
                raise Exception('Cannot add entry to service database : url already present in the database')

        if id is not None:
            entries = list(filter(lambda entry: entry['id']==id , self.data.values()))
            if len(entries) >0:
                logger.exception('Cannot add entry to service database : id already present in the database')
                raise Exception('Cannot add entry to service database : id already present in the database')

        # all good to add the new entry
        self.data[name] = {'id' : id, 'url': url}

    #--------------------------------------------
    #--------------------------------------------
    
    def get_info(self, name = None, id = None, url = None):
        """ Get info for an entry: Order of precendence for search : name > url > id.
        Return a dictonary with all three fields - name, id and url - as found in the database"""

        if name is not None:
            if name in self.data.keys():
                info = copy.deepcopy(self.data[name])
                info.update({'name': name})
                return info
        elif url is not None:
           entries = list(filter(lambda entry: are_the_urls_same(entry[1]['url'], url) , list(self.data.items())))
           if len(entries) >1:
                logger.exception('Cannot get info: Invalid Database, url found multiple times in the database')
                raise Exception('Cannot get info: Invalid Database, url found multiple times in the database')
           if len(entries) ==1: 
               info = copy.deepcopy(entries[0][1])
               info.update({'name': entries[0][0]})
               return info
        elif id is not None:
            entries = list(filter(lambda entry: entry[1]['id']==id , list(self.data.items())))
            if len(entries) >1:
                logger.exception('Cannot get info: Invalid Database, id found multiple times in the database')
                raise Exception('Cannot get info: Invalid Database, id found multiple times in the database')
            if len(entries) ==1: 
               info = copy.deepcopy(entries[0][1])
               info.update({'name': entries[0][0]})
               return info
        else:
            logger.exception('Cannot get info: No corresponding entry in the database')
            raise Exception('Cannot get info: No corresponding entry in the database')

    #--------------------------------------------
    #--------------------------------------------

    def update_info(self, name, id = None, url = None):
        """Update id or url of a specific service identified by name. Return new info"""
        if name is not None:
            if name in self.data.keys():
                if id is not None:
                    self.data[name]['id'] = id
                if url is not None:
                    self.data[name]['url'] = url
                return self.get_info(name)
        else:
            logger.exception('Cannot update info: No corresponding entry in the database for the given name')
            raise Exception('Cannot update info: No corresponding entry in the database for the given name')
    
    #--------------------------------------------
    #--------------------------------------------
    
    def remove_info(self, name = None, id = None, url = None):
        """Remove all entries corresponding to name & id & url. Return number of entries removed"""

        num_removed = 0
        # remove by name
        if self.data.pop(name, None):
            num_removed+=1

        # remove by id
        entries = list(filter(lambda entry: entry[1]['id']==id , list(self.data.items())))
        for entry in entries:
            self.data.pop(entry[0])
        num_removed+=len(entries)

        #remove by url
        entries = list(filter(lambda entry: are_the_urls_same(entry[1]['url'], url) , list(self.data.items()))) 
        for entry in entries:
            self.data.pop(entry[0])
        num_removed+=len(entries)

        return num_removed

        
  
    
        

    
