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

import hashlib

import logging
logger = logging.getLogger(__name__)

__all__ = [
    'clear_all_data',
    'load_database',
    'save_database',
    'add_by_url',
    'remove_by_name',
    'remove_by_enclave_id',
    'rename_enclave',
    'get_enclave_ids',
    'get_enclave_names',
    'get_by_name',
    'get_by_enclave_id',
    ]

from pdo.submitter.create import create_submitter
from pdo.service_client.enclave import EnclaveServiceClient
from pdo.common.utility import deprecated

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class enclave_info(object) :
    """The enclave_info class holds information about an enclave
    including the identity, a human readable name given by the user,
    the URL of the eservice that hosts the enclave, and the time when
    the enclave information was last verified.
    """

    @classmethod
    def deserialize(cls, serialized) :
        enclave_id = serialized['enclave_id']
        name = serialized['name']
        url = serialized['url']
        last_verified_time = serialized['last_verified_time']
        return cls(enclave_id, name, url, last_verified_time)

    @staticmethod
    def __hashed_identity__(enclave_id) :
        return hashlib.sha256(enclave_id.encode('utf8')).hexdigest()[:16]

    def __init__(self, enclave_id, name = "", url = "", last_verified_time = "", client = None) :
        self.enclave_id = enclave_id
        self.name = name
        self.url = url
        self.last_verified_time = last_verified_time

        if self.name == '' :
            self.name = enclave_info.__hashed_identity__(self.enclave_id)

        self.__eservice_client__ = client

    @property
    def client(self) :
        if self.__eservice_client__ is None :
            self.__eservice_client__ = EnclaveServiceClient(self.url)
        return self.__eservice_client__

    @client.setter
    def client(self, c) :
        self.__eservice_client__ = c

    def verify(self, ledger_config) :
        """ensure that the eservice still exists and hosts the enclave, and
        ensure that the enclave is registered with the ledger
        """

        # first check: make sure the enclave hosted by the eservice is
        # the one we expect to be hosted
        try :
            if self.client.enclave_id != self.enclave_id :
                logger.info('mismatched enclave ids')
                self.last_verified_time = None
                return False
        except Exception as e :
            logger.info('failed to retrieve information from the hosting eservice; %s', str(e))
            self.last_verified_time = ""
            return False

        # second check: make sure the ledger has an entry for the enclave
        if ledger_config and ledger_config.get('LedgerURL') :
            try :
                registry_helper = create_submitter(ledger_config)
                enclave_state = registry_helper.get_enclave_info(self.enclave_id)
            except Exception as e :
                logger.info('failed to verify enclave registration with the ledger; %s', str(e))
                self.last_verified_time = ""
                return False
        else :
            logger.info('skipping ledger verification, no ledger specified')

        self.last_verified_time = str(datetime.datetime.now())
        return True

    def serialize(self) :
        """convert the object into a dictionary
        """
        serialized = dict()
        serialized['enclave_id'] = self.enclave_id
        serialized['name'] = self.name
        serialized['url'] = self.url
        serialized['last_verified_time'] = self.last_verified_time

        return serialized

# -----------------------------------------------------------------
# __data__ is the primary data storage for the in-memory eservice
# database; it maps enclave_id to the corresponding enclave info
# object
# -----------------------------------------------------------------
__data__ = dict()

# -----------------------------------------------------------------
# __enclave_name_map__ is the secondary key for the in-memory
# eservice database; it maps a name to an enclave_id
# -----------------------------------------------------------------
__enclave_name_map__ = dict()

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def __remove_einfo_object__(einfo) :
    """guarantee that the enclave_id and name mappings are clear
    for the enclave
    """

    global __data__, __enclave_name_map__

    try :
        # we use the old information because the name may change
        # in the new enclave (though the enclave_id will not)
        old_einfo = __data__[einfo.enclave_id]
        __data__.pop(einfo.enclave_id, None)
        __enclave_name_map__.pop(old_einfo.name, None)
    except :
        pass

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def __add_einfo_object__(einfo, update=False) :
    """add an enclave_info object to the in memory database and update
    the name mappings as appropriate
    """

    global __data__, __enclave_name_map__

    if update :
        # this convoluted check ensures that the name of the new enclave
        # is not already being used to identify an existing enclave that
        # is different than the one being added, this update is prohibited
        if __enclave_name_map__.get(einfo.name, einfo.enclave_id) != einfo.enclave_id :
            raise Exception('attempt to rename existing enclave')

        __remove_einfo_object__(einfo)

    # this is not quite guaranteed if update because the name may be
    # used for a different enclave so it must always be checked
    if einfo.enclave_id in __data__ or einfo.name in __enclave_name_map__ :
        raise Exception('duplicate eservice entry; {0}'.format(einfo.name))

    __data__[einfo.enclave_id] = einfo
    __enclave_name_map__[einfo.name] = einfo.enclave_id

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def clear_all_data():
    """Clear the in-memory database and all secondary indexes. Useful
    to create a fresh database.
    """

    global __data__, __enclave_name_map__

    __data__ = dict()
    __enclave_name_map__ = dict()

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def load_database(filename, merge = True):
    """Load enclave information into the in-memory database from
    a file that contains json serialization of enclave_info objects.

    The function returns True, if the load succeeds or False if it
    fails. On failure the old database is restored.
    """
    global __data__, __enclave_name_map__

    try :
        with open(filename, 'r') as fp:
            serialized_einfo_list = json.load(fp)
    except Exception as e :
        logger.error('failed to load the database from file %s', filename)
        return False

    original_data = __data__.copy()
    original_enclave_name_map = __enclave_name_map__.copy()

    if not merge :
        clear_all_data()

    try :
        for serialized_einfo in serialized_einfo_list :
            einfo_object = enclave_info.deserialize(serialized_einfo)
            __add_einfo_object__(einfo_object, update=merge)
    except Exception as e :
        logger.error('failed to add enclave info from the database file %s; %s', filename, str(e))
        __data__ = original_data
        __enclave_name_map__ = original_enclave_name_map
        return False

    return True

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def save_database(filename, overwrite = False):
    """Serialize the in-memory enclave information database and write
    it to a file. Data will be serialized as JSON.
    """

    if os.path.exists(filename) and overwrite is False:
        logger.error('Cannot save database to file. File already present')
        return False

    serialized_einfo_list = []
    for enclave_id, einfo in __data__.items() :
        serialized_einfo = einfo.serialize()
        serialized_einfo_list.append(serialized_einfo)

    # dump json to temporary file, if write succeeds move to desired file
    temp_filename = filename + '_temp'
    try:
        with open(temp_filename, 'w') as fp:
            json.dump(serialized_einfo_list, fp)
        shutil.move(temp_filename, filename)
    except Exception as e:
        raise Exception('Failed to save service database info as a json file: %s', str(e))

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def add_by_url(ledger_config, url, name='', update=False) :
    """add to the in-memory database information about the enclave
    hosted by an eservice at the provided url.
    """
    try :
        client = EnclaveServiceClient(url)
    except Exception as e :
        logger.error('unable to connect to enclave service; %s', str(e))
        return None

    einfo = enclave_info(client.enclave_id, name=name, url=url, client=client)
    try :
        if not einfo.verify(ledger_config) :
            logger.info('enclave verification failed for url %s', url)
            return None

        __add_einfo_object__(einfo, update)
        return einfo

    except Exception as e :
        logger.exception('add_by_url')

    return None

@deprecated
def add_info_to_database(name,  url, ledger_config):
    return add_by_url(ledger_config, url, name, update=False)

@deprecated
def update_info_in_database(name, url, ledger_config):
    return add_by_url(ledger_config, url, name, update=True)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def remove_by_name(name) :
    try :
        einfo = get_by_name(name)
        __remove_einfo_object__(einfo)
        return True
    except :
        pass

    return False

def remove_by_enclave_id(enclave_id) :
    try :
        einfo = get_by_enclave_id(enclave_id)
        __remove_einfo_object__(einfo)
        return True
    except :
        pass

    return False

@deprecated
def remove_info_from_database(name = '', enclave_id = None, url = None):
    """ Remove entries corresponding to name & id & url. Return the number of entries removed"""
    if name :
        return remove_by_name(name)

    if enclave_id :
        return remove_by_enclave_id(enclave_id)

    logger.info('failed to remove enclave for url %s', url)
    return False

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def rename_enclave(old_name, new_name) :
    einfo = get_by_name(old_name)
    if einfo is None :
        return False

    try :
        # update the object and add the new enclave info mapping, the
        # the update flag will ensure that the old version of the
        # enclave_info will be removed
        einfo.name = new_name
        __add_einfo_object__(einfo, update=True)
    except Exception as e :
        logger.info('failed to rename enclave %s to %s', old_name, new_name)
        return False

    return True

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def get_enclave_ids() :
    return __data__.keys()

def get_enclave_names() :
    return __enclave_name_map__.keys()

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def get_by_name(name) :
    enclave_id = __enclave_name_map__.get(name)
    return get_by_enclave_id(enclave_id)

def get_by_enclave_id(enclave_id) :
    return __data__.get(enclave_id)

@deprecated
def get_info_by_name(name):
    """ Get service info as present in database using name. Returns a dictonary with four fields:
    name, id, url, last_verified_time. Return None if there is no matching entry. """

    einfo = get_by_name(name)
    if einfo :
        return einfo.serialize()

    return None

@deprecated
def get_info_by_id(enclave_id):
    """ Get service info as present in database using id. Returns a dictonary with four fields:
    name, id, url, last_verified_time. Return None if there is no matching entry. """

    einfo = get_by_enclave_id(enclave_id)
    if einfo :
        return einfo.serialize()

    return None

@deprecated
def get_info_by_url(url):
    """ Get service info as present in database using url. Returns a dictonary with four fields:
    name, id, url, last_verified_time. Return None if there is no matching entry. """

    return None

@deprecated
def get_client_by_name(name):
    """ get client for eservice identified by name"""

    einfo = get_by_name(name)
    if einfo :
        return einfo.client

    return None

@deprecated
def get_client_by_url(url):
    """ get client for eservice@url"""

    try :
        return EnclaveServiceClient(url)
    except Exception as e :
        raise Exception('Cannot generate client for eservice at %s: %s', str(url), str(e))

@deprecated
def get_client_by_id(enclave_id):
    """ get client for eservice identified by id"""

    einfo = get_by_enclave_id(enclave_id)
    if einfo :
        return einfo.client

    return None
