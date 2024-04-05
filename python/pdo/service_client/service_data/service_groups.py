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
import json
import lmdb

import pdo.common.config as pconfig

from pdo.service_client.service_data.service_data import ServiceDatabaseManager as service_data
from pdo.common.utility import classproperty

import logging
logger = logging.getLogger(__name__)

## =================================================================
## SERVICE GROUP CLASSES
## =================================================================

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class BaseGroup(object) :
    @staticmethod
    def force_to_bytes(s) :
        return s if isinstance(s, bytes) else bytes(s, 'utf-8')

    @staticmethod
    def force_to_string(s) :
        return s if isinstance(s, str) else s.decode('ascii')

    @classmethod
    def unpack(cls, group_name, json_encoded_info) :
        service_info = json.loads(json_encoded_info)
        return cls(group_name, **service_info)

    def __init__(self, service_type, group_name, urls) :
        self.group_name = BaseGroup.force_to_string(group_name)
        self.service_type = BaseGroup.force_to_string(service_type)
        self.service_urls = list(map(lambda url : BaseGroup.force_to_string(url), urls))

    def pack(self) :
        return BaseGroup.force_to_bytes(json.dumps(self.serialize()))

    def serialize(self) :
        service_info = {}
        service_info['service_type'] = self.service_type
        service_info['urls'] = self.service_urls
        return service_info

    def verify(self) :
        """Verify that the URLs in the group are all part of the service db

        Raises an exception if verification fails. Note that this only checks
        if the URLs currently exist in the database. There is no enforcement
        for future changes.
        """
        for u in self.service_urls :
            _ = service_data.local_service_manager.get_by_url(u, self.service_type)

    def clone(self) :
        return type(self).unpack(self.serialize())

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class EnclaveServiceGroup(BaseGroup) :
    def __init__(self, group_name, urls, **kwargs) :
        super().__init__('eservice', group_name, urls)
        self.preferred = BaseGroup.force_to_string(kwargs.get('preferred', 'random'))

    def serialize(self) :
        serialized = super().serialize()
        serialized['preferred'] = self.preferred
        return serialized

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ProvisioningServiceGroup(BaseGroup) :
    def __init__(self, group_name, urls, **kwargs) :
        super().__init__('pservice', group_name, urls)

    def serialize(self) :
        serialized = super().serialize()
        return serialized

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class StorageServiceGroup(BaseGroup) :
    def __init__(self, group_name, urls, **kwargs) :
        super().__init__('sservice', group_name, urls)
        self.replicas = int(kwargs.get('replicas', 2))
        self.duration = int(kwargs.get('duration', 120))
        self.persistent = BaseGroup.force_to_string(kwargs.get('persistent', ''))

    def serialize(self) :
        serialized = super().serialize()
        serialized['replicas'] = self.replicas
        serialized['duration'] = self.duration
        serialized['persistent'] = self.persistent
        return serialized

## =================================================================
## DATABASE ROUTINES
## =================================================================

# -----------------------------------------------------------------
# The service database contains five stores which include three for
# the services (one each for eservice, pservice, and sservice), one
# to map service identities (often the verifying key for the service)
# to its URL, and one to map a human readable name to a service url.
# -----------------------------------------------------------------
class GroupsDatabaseManager(object) :
    map_size = 1 << 40
    service_types = set(['eservice', 'pservice', 'sservice'])
    service_group_map = {
        'eservice' : EnclaveServiceGroup,
        'pservice' : ProvisioningServiceGroup,
        'sservice' : StorageServiceGroup
    }

    # this provides a means for running a specific instance of the GroupsDatabaseManager
    # as a service for all applications; it will only be instantiated on first use
    __local_groups_manager__ = None

    # -----------------------------------------------------------------
    @classproperty
    def local_groups_manager(cls) :
        if cls.__local_groups_manager__ is None :
            groups_db_file = pconfig.shared_configuration(['Service', 'GroupDatabaseFile'], "./groups_db.mdb")
            cls.__local_groups_manager__ = cls(groups_db_file, True)

            atexit.register(cls.__local_groups_manager__.close)

        return cls.__local_groups_manager__

    # -----------------------------------------------------------------
    def __init__(self, groups_db_file, create_groups_db=True) :
        """Initialize service database instance

        :param groups_db_file string: name of the lmdb file used for service storage
        :param create_groups_db boolean: flag to note that missing db file should be created
        """
        self.groups_db_file = groups_db_file
        self.groups_db_env = lmdb.open(
            self.groups_db_file,
            create=create_groups_db,
            max_dbs=5,
            subdir=False,
            sync=False,
            map_size=self.map_size)

    # -----------------------------------------------------------------
    def close(self) :
        """close the database file
        """

        # This should be locked
        if self.groups_db_env :
            self.groups_db_env.sync()
            self.groups_db_env.close()
            self.groups_db_env = None

    # -----------------------------------------------------------------
    def groups_db(self, service_type) :
        service_type = BaseGroup.force_to_string(service_type)
        return self.groups_db_env.open_db(BaseGroup.force_to_bytes("{}_data".format(service_type)))

    # -----------------------------------------------------------------
    def unpack_group_info(self, group_name, packed_group_info, service_type) :
        info_class = GroupsDatabaseManager.service_group_map[service_type]
        return info_class.unpack(group_name, packed_group_info)

    # -----------------------------------------------------------------
    def update(self, group_info : BaseGroup) :
        """Add information about a group, overwriting any existing group information

        The update operation is effectively the same as the store operation except
        that update overwrites an existing entry, while store fails.
        """

        # make sure that all of the URLs are registered in the service_db
        group_info.verify()

        groups_db = self.groups_db(group_info.service_type)
        with self.groups_db_env.begin(write=True) as txn :
            group_name = BaseGroup.force_to_bytes(group_info.group_name)
            if not txn.put(group_name, group_info.pack(), overwrite=True, db=groups_db) :
                raise Exception("failed to save group; {}".format(group_info.group_name))

    # -----------------------------------------------------------------
    def store(self, group_info) :

        # make sure that all of the URLs are registered in the service_db
        group_info.verify()

        groups_db = self.groups_db(group_info.service_type)
        with self.groups_db_env.begin(write=True) as txn :
            group_name = BaseGroup.force_to_bytes(group_info.group_name)
            if not txn.put(group_name, group_info.pack(), overwrite=False, db=groups_db) :
                raise Exception("failed to save service information; {}".format(group_info.service_urls))

    # -----------------------------------------------------------------
    def remove(self, group_info) :

        groups_db = self.groups_db(group_info.service_type)
        with self.groups_db_env.begin(write=True) as txn :
            group_name = BaseGroup.force_to_bytes(group_info.group_name)
            txn.delete(group_name, db=groups_db)

    # -----------------------------------------------------------------
    def reset(self) :
        sgroups_db = self.groups_db_env.open_db(b'sservice_data')
        pgroups_db = self.groups_db_env.open_db(b'pservice_data')
        egroups_db = self.groups_db_env.open_db(b'eservice_data')

        with self.groups_db_env.begin(write=True) as txn :
            txn.drop(egroups_db)
            txn.drop(pgroups_db)
            txn.drop(sgroups_db)

    # -----------------------------------------------------------------
    def get_by_name(self, group_name, service_type = 'eservice') :
        if service_type not in self.service_types :
            raise RuntimeError('unknown service type {}'.format(service_type))

        groups_db = self.groups_db(service_type)
        with self.groups_db_env.begin(write=False) as txn :
            packed_group_data = txn.get(BaseGroup.force_to_bytes(group_name), db=groups_db)
            if packed_group_data is None :
                raise RuntimeError('no such {} {}'.format(service_type, group_name))

        return self.unpack_group_info(group_name, packed_group_data, service_type)

    # -----------------------------------------------------------------
    def list_groups(self, service_type = 'eservice') :
        if service_type not in self.service_types :
            raise RuntimeError('unknown service type {}'.format(service_type))

        groups_db = self.groups_db(service_type)
        with self.groups_db_env.begin(write=False) as txn :
            cursor = txn.cursor(db=groups_db)
            for group_name, packed_group_data in cursor :
                yield (BaseGroup.force_to_string(group_name),
                       self.unpack_group_info(group_name, packed_group_data, service_type))

    # -----------------------------------------------------------------
    def import_group_information(self, groups) :
        """Bulk add of services to the database
        """

        group_file_keys = [
            ('eservice', 'EnclaveServiceGroups'),
            ('pservice', 'ProvisioningServiceGroups'),
            ('sservice', 'StorageServiceGroups'),
        ]

        for (service_type, group_label) in group_file_keys :
            service_group_list = groups.get(group_label, {})
            for group_name, group_info in service_group_list.items() :
                # if the old entry exists, remove it before we import the new entry
                # note that this import is not fully transactional
                try :
                    old_group_info = self.get_by_name(group_name, service_type)
                    self.remove(old_group_info)
                except :
                    pass

                try :
                    group_info = self.service_group_map[service_type](group_name, **group_info)
                    self.store(group_info)
                except :
                    logger.warning('failed to import {} group {}'.format(service_type, group_name))

    # -----------------------------------------------------------------
    def export_group_information(self) :
        """Bulk dump of all services from the database
        """

        service_file_keys = [
            ('eservice', 'EnclaveServiceGroups'),
            ('pservice', 'ProvisioningServiceGroups'),
            ('sservice', 'StorageServiceGroups'),
        ]

        groups = {}
        for (service_type, group_label) in service_file_keys :
            groups[group_label] = {}

            for (group_name, group_info) in self.list_groups(service_type=service_type) :
                groups[group_label][BaseGroup.force_to_string(group_name)] = group_info.serialize()

        return groups
