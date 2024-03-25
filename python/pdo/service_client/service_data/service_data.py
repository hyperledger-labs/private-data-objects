#!/usr/bin/env python

# Copyright 2023 Intel Corporation
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

import atexit
import datetime
from functools import lru_cache
import json
import lmdb
import os

import pdo.common.config as pconfig
import pdo.common.logger as plogger

from pdo.service_client.enclave import EnclaveServiceClient
from pdo.service_client.provisioning import ProvisioningServiceClient
from pdo.service_client.storage import StorageServiceClient
from pdo.common.utility import classproperty
from pdo.submitter.create import create_submitter

from urllib.parse import urlparse

# -----------------------------------------------------------------
# -----------------------------------------------------------------
@lru_cache(maxsize=16)
def get_service_client(service_type, url) :
    """Get a handle to a service client for the specified URL, handles
    are managed through an LRU cache so re-use should be acceptable
    """
    if service_type == 'eservice' :
        return EnclaveServiceClient(url)
    elif service_type == 'pservice' :
        return ProvisioningServiceClient(url)
    elif service_type == 'sservice' :
        return StorageServiceClient(url)
    else :
        raise Exception("unknown service client")

## =================================================================
## SERVICE INFORMATION CLASSES
## =================================================================

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class BaseInfo(object) :
    @staticmethod
    def force_to_bytes(s) :
        return s if isinstance(s, bytes) else bytes(s, 'utf-8')

    @staticmethod
    def force_to_string(s) :
        return s if isinstance(s, str) else s.decode('ascii')

    @classmethod
    def unpack(cls, url, json_encoded_info) :
        service_info = json.loads(json_encoded_info)
        return cls(**service_info)

    def __init__(self, service_type, service_url, service_identity, service_names=[], last_verified_time=0) :
        self.service_type = BaseInfo.force_to_string(service_type)
        self.service_url = BaseInfo.force_to_string(service_url)
        self.service_identity = BaseInfo.force_to_string(service_identity)
        self.service_names = set(map(lambda n : BaseInfo.force_to_string(n), service_names))
        self.last_verified_time = last_verified_time

    def pack(self) :
        return BaseInfo.force_to_bytes(json.dumps(self.serialize()))

    def serialize(self) :
        service_info = {}
        service_info['service_type'] = self.service_type
        service_info['service_url'] = self.service_url
        service_info['service_identity'] = self.service_identity
        service_info['service_names'] = list(self.service_names)
        service_info['last_verified_time'] = self.last_verified_time
        return service_info

    def verified(self) :
        return self.last_verified_time > 0

    def client(self) :
        return get_service_client(self.service_type, self.service_url)

    def add_service_name(self, service_name) :
        self.service_names.add(BaseInfo.force_to_string(service_name))

    def remove_service_name(self, service_name) :
        self.service_names.discard(BaseInfo.force_to_string(service_name))

    def clone(self) :
        return type(self).unpack(self.service_url, self.pack())

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class EnclaveServiceInfo(BaseInfo) :
    @classmethod
    def fetch_service_info(cls, url, service_names=[], service_identity=None) :
        client = get_service_client('eservice', url)
        if service_identity and client.enclave_id != service_identity :
            raise RuntimeError("provided identity does not match service")

        new_info = cls(url, client.enclave_id, service_names=service_names)

        # although we are picking up the information from the
        # eservice here, we still need to verify it with the
        # ledger; this creates a bit of redundancy but if we
        # assume the connection is cached it shouldn't be much
        # of a performance burden
        new_info.last_verified_time = 0

        new_info.verifying_key = BaseInfo.force_to_string(client.verifying_key)
        new_info.encryption_key = BaseInfo.force_to_string(client.encryption_key)
        new_info.interpreter = BaseInfo.force_to_string(client.interpreter)
        new_info.storage_service_url = BaseInfo.force_to_string(client.storage_service_url)

        return new_info

    def __init__(self, service_url, service_identity, **kwargs) :
        service_names = kwargs.get('service_names', [])
        last_verified_time = kwargs.get('last_verified_time', 0)
        super().__init__('eservice', service_url, service_identity, service_names, last_verified_time)

        self.verifying_key = BaseInfo.force_to_string(kwargs.get('verifying_key', ''))
        self.encryption_key = BaseInfo.force_to_string(kwargs.get('encryption_key', ''))
        self.interpreter = BaseInfo.force_to_string(kwargs.get('interpreter', ''))
        self.storage_service_url = BaseInfo.force_to_string(kwargs.get('storage_service_url', ''))

    def serialize(self) :
        serialized = super().serialize()
        serialized['verifying_key'] = self.verifying_key
        serialized['encryption_key'] = self.encryption_key
        serialized['interpreter'] = self.interpreter
        serialized['storage_service_url'] = self.storage_service_url
        return serialized

    def verify(self, ledger_config = None) :
        """ensure that the eservice still exists and hosts the enclave, and
        ensure that the enclave is registered with the ledger
        """

        if ledger_config is None :
            ledger_config = pconfig.shared_configuration(['Ledger'])

        # the information we are retreiving must be verified
        self.last_verified_time = 0

        # first check: make sure the enclave hosted by the eservice is
        # the one we expect to be hosted
        client = self.client()
        if client.enclave_id != self.service_identity :
            return False
        if client.interpreter != self.interpreter :
            return False
        if client.verifying_key != self.verifying_key :
            return False
        if client.encryption_key != self.encryption_key :
            return False

        # storage URL need not be consistent, just copy the current reference
        self.storage_service_url = client.storage_service_url

        # second check: make sure the ledger has an entry for the enclave
        # and that the information stored for the enclave matches
        ledger = create_submitter(ledger_config)
        enclave_state = ledger.get_enclave_info(self.service_identity)
        if enclave_state['verifying_key'] != self.verifying_key :
            return False
        if enclave_state['encryption_key'] != self.encryption_key :
            return False

        self.last_verified_time = int(round(datetime.datetime.now().timestamp()))
        return True

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ProvisioningServiceInfo(BaseInfo) :
    @classmethod
    def fetch_service_info(cls, url, service_names=[], service_identity=None) :
        client = get_service_client('pservice', url)
        if service_identity and client.identity != service_identity :
            raise RuntimeError("provided identity does not match service")

        new_info = cls(url, client.identity, service_names=service_names)

        # the information we are retreiving must be verified
        new_info.last_verified_time = 0
        new_info.verifying_key = BaseInfo.force_to_string(client.verifying_key)

        return new_info

    def __init__(self, service_url, service_identity, **kwargs) :
        service_names = kwargs.get('service_names', [])
        last_verified_time = kwargs.get('last_verified_time', 0)
        super().__init__('pservice', service_url, service_identity, service_names, last_verified_time)

        self.verifying_key = BaseInfo.force_to_string(kwargs.get('verifying_key', ''))

    def serialize(self) :
        serialized = super().serialize()
        serialized['verifying_key'] = self.verifying_key
        return serialized

    def verify(self, ledger_config = None) :
        """ensure that the eservice still exists and hosts the enclave, and
        ensure that the enclave is registered with the ledger
        """

        if ledger_config is None :
            ledger_config = pconfig.shared_configuration(['Ledger'])

        # the information we are retreiving must be verified
        self.last_verified_time = 0

        # first check: make sure the enclave hosted by the eservice is
        # the one we expect to be hosted
        client = self.client()
        if client.verifying_key != self.verifying_key :
            return False

        self.last_verified_time = int(round(datetime.datetime.now().timestamp()))
        return True

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class StorageServiceInfo(BaseInfo) :
    @classmethod
    def fetch_service_info(cls, url, service_names=[], service_identity=None) :
        client = get_service_client('sservice', url)
        if service_identity and client.verifying_key != service_identity :
            raise RuntimeError("provided identity does not match service")

        new_info = cls(url, client.verifying_key, service_names=service_names)

        # the information we are retreiving must be verified
        new_info.last_verified_time = 0
        new_info.verifying_key = BaseInfo.force_to_string(client.verifying_key)

        return new_info

    def __init__(self, service_url, service_identity, **kwargs) :
        service_names = kwargs.get('service_names', [])
        last_verified_time = kwargs.get('last_verified_time', 0)
        super().__init__('sservice', service_url, service_identity, service_names, last_verified_time)

        self.verifying_key = BaseInfo.force_to_string(kwargs.get('verifying_key', ''))
        # will add information about duration etal when it is exported

    def serialize(self) :
        serialized = super().serialize()
        serialized['verifying_key'] = self.verifying_key
        return serialized

    def verify(self, ledger_config = None) :
        """ensure that the sservice still exists and still has the
        same verifying key
        """

        if ledger_config is None :
            ledger_config = pconfig.shared_configuration(['Ledger'])

        # the information we are retreiving must be verified
        self.last_verified_time = 0

        # first check: make sure the enclave hosted by the eservice is
        # the one we expect to be hosted
        client = self.client()
        if client.verifying_key != self.verifying_key :
            return False

        self.last_verified_time = int(round(datetime.datetime.now().timestamp()))
        return True

## =================================================================
## DATABASE ROUTINES
## =================================================================

# -----------------------------------------------------------------
# The service database contains five stores which include three for
# the services (one each for eservice, pservice, and sservice), one
# to map service identities (often the verifying key for the service)
# to its URL, and one to map a human readable name to a service url.
# -----------------------------------------------------------------
class ServiceDatabaseManager(object) :
    map_size = 1 << 40
    service_types = set(['eservice', 'pservice', 'sservice'])
    service_info_map = {
        'eservice' : EnclaveServiceInfo,
        'pservice' : ProvisioningServiceInfo,
        'sservice' : StorageServiceInfo
    }

    # this provides a means for running a specific instance of the ServiceDatabaseManager
    # as a service for all applications; it will only be instantiated on first use
    __local_service_manager__ = None

    # -----------------------------------------------------------------
    @classproperty
    def local_service_manager(cls) :
        if cls.__local_service_manager__ is None :
            service_db_file = pconfig.shared_configuration(['Service','ServiceDatabaseFile'], "./service_db.mdb")
            cls.__local_service_manager__ = cls(service_db_file, True)

            atexit.register(cls.__local_service_manager__.close)

        return cls.__local_service_manager__

    # -----------------------------------------------------------------
    def __init__(self, service_db_file, create_service_db=True) :
        """Initialize service database instance

        :param service_db_file string: name of the lmdb file used for service storage
        :param create_service_db boolean: flag to note that missing db file should be created
        """
        self.service_db_file = service_db_file
        self.service_db_env = lmdb.open(
            self.service_db_file,
            create=create_service_db,
            max_dbs=5,
            subdir=False,
            sync=False,
            map_size=self.map_size)

    # -----------------------------------------------------------------
    def close(self) :
        """close the database file
        """

        # This should be locked
        if self.service_db_env :
            self.service_db_env.sync()
            self.service_db_env.close()
            self.service_db_env = None

    # -----------------------------------------------------------------
    def service_db(self, service_type) :
        service_type = BaseInfo.force_to_string(service_type)
        return self.service_db_env.open_db(BaseInfo.force_to_bytes("{}_data".format(service_type)))

    # -----------------------------------------------------------------
    def unpack_service_info(self, url, packed_service_info, service_type) :
        info_class = ServiceDatabaseManager.service_info_map[service_type]
        return info_class.unpack(url, packed_service_info)

    # -----------------------------------------------------------------
    def update(self, old_service_info, new_service_info) :
        """replace an old service info entry with a new one
        Note : update  is not quite the same as calling remove and store
        separately because this entire operation is performed in a single
        transaction... so it either works completely or not at all
        """

        assert old_service_info.service_type == new_service_info.service_type

        service_db = self.service_db(old_service_info.service_type)
        identity_db = self.service_db_env.open_db(b'identity_index')
        name_db = self.service_db_env.open_db(b'name_index')

        with self.service_db_env.begin(write=True) as txn :
            # remove the old entry
            old_service_identity = BaseInfo.force_to_bytes(old_service_info.service_identity)
            txn.delete(old_service_identity, db=identity_db)

            for n in old_service_info.service_names :
                n = BaseInfo.force_to_bytes(n)
                txn.delete(n, db=name_db)

            old_service_url = BaseInfo.force_to_bytes(old_service_info.service_url)
            txn.delete(old_service_url, db=service_db)

            # store the new one
            service_url = BaseInfo.force_to_bytes(new_service_info.service_url)
            service_identity = BaseInfo.force_to_bytes(new_service_info.service_identity)
            if not txn.put(service_identity, service_url, overwrite=False, db=identity_db) :
                raise Exception("failed to save service identity; {}".format(new_service_info.service_identity))

            for n in new_service_info.service_names :
                n = BaseInfo.force_to_bytes(n)
                if not txn.put(n, service_url, overwrite=False, db=name_db) :
                    raise Exception("failed to save service name; {}".format(n))

            if not txn.put(service_url, new_service_info.pack(), overwrite=False, db=service_db) :
                raise Exception("failed to save service information; {}".format(service_url))

    # -----------------------------------------------------------------
    def store(self, service_info) :

        service_db = self.service_db(service_info.service_type)
        identity_db = self.service_db_env.open_db(b'identity_index')
        name_db = self.service_db_env.open_db(b'name_index')

        with self.service_db_env.begin(write=True) as txn :
            service_url = BaseInfo.force_to_bytes(service_info.service_url)

            service_identity = BaseInfo.force_to_bytes(service_info.service_identity)
            if not txn.put(service_identity, service_url, overwrite=False, db=identity_db) :
                raise Exception("failed to save service identity; {}".format(service_info.service_identity))

            for n in service_info.service_names :
                n = BaseInfo.force_to_bytes(n)
                if not txn.put(n, service_url, overwrite=False, db=name_db) :
                    raise Exception("failed to save service name; {}".format(n))

            if not txn.put(service_url, service_info.pack(), overwrite=False, db=service_db) :
                raise Exception("failed to save service information; {}".format(service_info.service_url))

    # -----------------------------------------------------------------
    def remove(self, service_info) :
        service_db = self.service_db(service_info.service_type)
        identity_db = self.service_db_env.open_db(b'identity_index')
        name_db = self.service_db_env.open_db(b'name_index')

        with self.service_db_env.begin(write=True) as txn :
            service_identity = BaseInfo.force_to_bytes(service_info.service_identity)
            txn.delete(service_identity, db=identity_db)

            for n in service_info.service_names :
                n = BaseInfo.force_to_bytes(n)
                txn.delete(n, db=name_db)

            service_url = BaseInfo.force_to_bytes(service_info.service_url)
            txn.delete(service_url, db=service_db)

    # -----------------------------------------------------------------
    def reset(self) :
        identity_db = self.service_db_env.open_db(b'identity_index')
        name_db = self.service_db_env.open_db(b'name_index')
        sservice_db = self.service_db_env.open_db(b'sservice_data')
        pservice_db = self.service_db_env.open_db(b'pservice_data')
        eservice_db = self.service_db_env.open_db(b'eservice_data')

        with self.service_db_env.begin(write=True) as txn :
            txn.drop(identity_db)
            txn.drop(name_db)
            txn.drop(eservice_db)
            txn.drop(pservice_db)
            txn.drop(sservice_db)

    # -----------------------------------------------------------------
    def get_by_url(self, url, service_type = 'eservice') :
        if service_type not in self.service_types :
            raise RuntimeError('unknown service type {}'.format(service_type))

        # canonicalize the url format
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]) :
            raise RuntimeError("invalid url; {}", url)

        (hostname, hostport) = parsed_url.netloc.split(':')
        service_url = "http://{}:{}".format(hostname, hostport)

        service_db = self.service_db(service_type)
        with self.service_db_env.begin(write=False) as txn :
            packed_service_data = txn.get(BaseInfo.force_to_bytes(service_url), db=service_db)

        if packed_service_data is None :
            raise RuntimeError('no such {} {}'.format(service_type, service_url))

        return self.unpack_service_info(service_url, packed_service_data, service_type)

    # -----------------------------------------------------------------
    def get_by_identity(self, identity, service_type = 'eservice') :
        if service_type not in self.service_types :
            raise RuntimeError('unknown service type {}'.format(service_type))

        service_db = self.service_db(service_type)
        identity_db = self.service_db_env.open_db(b'identity_index')

        with self.service_db_env.begin(write=False) as txn :
            url = txn.get(BaseInfo.force_to_bytes(identity), db=identity_db)
            if url is None :
                raise RuntimeError('no such {} {}'.format(service_type, identity))
            packed_service_data = txn.get(url, db=service_db)

        if packed_service_data is None :
            raise RuntimeError('no such {} {}'.format(service_type, identity))

        return self.unpack_service_info(url, packed_service_data, service_type)

    # -----------------------------------------------------------------
    def get_by_name(self, service_name, service_type = 'eservice') :
        if service_type not in self.service_types :
            raise RuntimeError('unknown service type {}'.format(service_type))

        service_db = self.service_db(service_type)
        name_db = self.service_db_env.open_db(b'name_index')

        with self.service_db_env.begin(write=False) as txn :
            url = txn.get(BaseInfo.force_to_bytes(service_name), db=name_db)
            if url is None :
                raise RuntimeError('no such {} {}'.format(service_type, service_name))
            packed_service_data = txn.get(url, db=service_db)

        if packed_service_data is None :
            raise RuntimeError('no such {} {}'.format(service_type, service_name))

        return self.unpack_service_info(url, packed_service_data, service_type)

    # -----------------------------------------------------------------
    def list_services(self, service_type = 'eservice') :
        if service_type not in self.service_types :
            raise RuntimeError('unknown service type {}'.format(service_type))

        service_db = self.service_db(service_type)
        with self.service_db_env.begin(write=False) as txn :
            cursor = txn.cursor(db=service_db)
            for service_url, packed_service_data in cursor :
                yield (service_url, self.unpack_service_info(service_url, packed_service_data, service_type))

    # -----------------------------------------------------------------
    def store_by_url(self, url, service_type='eservice', service_names=[], service_identity=None) :
        if service_type not in self.service_types :
            raise RuntimeError('unknown service type {}'.format(service_type))

        # canonicalize the url format
        parsed_url = urlparse(url)
        if not all([parsed_url.scheme, parsed_url.netloc]) :
            raise RuntimeError("invalid url; {}", url)

        (hostname, hostport) = parsed_url.netloc.split(':')
        service_url = "http://{}:{}".format(hostname, hostport)

        info_class = ServiceDatabaseManager.service_info_map[service_type]
        service_info = info_class.fetch_service_info(service_url, service_names, service_identity)

        self.store(service_info)
        return service_info

    # -----------------------------------------------------------------
    def import_service_information(self, services) :
        """Bulk add of services to the database
        """

        service_file_keys = [
            ('eservice', 'EnclaveService'),
            ('pservice', 'ProvisioningService'),
            ('sservice', 'StorageService'),
        ]

        for (service_type, service_class) in service_file_keys :
            for import_service_info in services.get(service_class, []) :
                # make sure the URL has a valid format and canonicalize it
                parsed_url = urlparse(import_service_info["URL"])
                if not all([parsed_url.scheme, parsed_url.netloc]) :
                    raise RuntimeError("invalid entry in service information file; {}", import_service_info)

                (hostname, hostport) = parsed_url.netloc.split(':')
                service_url = "http://{}:{}".format(hostname, hostport)
                service_names = import_service_info.get("Names", [])
                service_identity = import_service_info.get("Identity")

                # if the old entry exists, remove it before we import the new entry
                # note that this import is not fully transactional
                try :
                    old_service_info = self.get_by_url(service_url, service_type)
                    self.remove(old_service_info)
                except :
                    pass

                self.store_by_url(
                    service_url,
                    service_type=service_type,
                    service_names=service_names,
                    service_identity=service_identity)

    # -----------------------------------------------------------------
    def export_service_information(self) :
        """Bulk dump of all services from the database
        """

        service_file_keys = [
            ('eservice', 'EnclaveService'),
            ('pservice', 'ProvisioningService'),
            ('sservice', 'StorageService'),
        ]

        services = {}
        for (service_type, service_class) in service_file_keys :
            services[service_class] = []
            for (service_url, service_info) in self.list_services(service_type=service_type) :
                export_service_info = {}
                export_service_info['URL'] = BaseInfo.force_to_string(service_info.service_url)
                export_service_info['Names'] = list(map(lambda n : BaseInfo.force_to_string(n), service_info.service_names))
                export_service_info['Identity'] = BaseInfo.force_to_string(service_info.service_identity)

                services[service_class].append(export_service_info)

        return services
