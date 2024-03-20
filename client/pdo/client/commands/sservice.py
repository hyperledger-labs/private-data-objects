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

import argparse
import logging

import pdo.common.config as pconfig
import pdo.common.utility as putils

import pdo.client.builder.shell as pshell
import pdo.client.builder.script as pscript
import pdo.client.commands.service_groups as pgroups
import pdo.client.commands.service_db as pservice

logger = logging.getLogger(__name__)

__all__ = [
    'get_replica_list',
    'get_replica_count',
    'get_replica_duration',
    'get_persistent_storage_service',
    'script_command_create',
    'script_command_create_from_site',
    'script_command_delete',
    'script_command_add',
    'script_command_remove',
    'script_command_set',
    'do_sservice',
    'load_commands',
]

## -----------------------------------------------------------------
def get_replica_list(state, sservice_group="default") :
    """create a list of urls for the services from the specified sservice group; assumes
    exception handling by the calling procedure
    """
    group_info = pgroups.get_group_info('sservice', sservice_group)

    sservice_url_list = set(group_info.service_urls)
    if group_info.persistent :
        sservice_url_list.add(group_info.persistent)

    return list(sservice_url_list)

## -----------------------------------------------------------------
def get_replica_count(state, sservice_group="default") :
    """return the replica count associated with the specified service group; defaults
    to the configuration for Replication
    """
    sservice_info = pgroups.get_group_info('sservice', sservice_group)
    return sservice_info.replicas

## -----------------------------------------------------------------
def get_replica_duration(state, sservice_group="default") :
    """return the minimum duration sservices are expected to hold a replica; this is
    pulled from the specified service group; defaults to the configuration for Replication
    """
    sservice_info = pgroups.get_group_info('sservice', sservice_group)
    return sservice_info.duration

## -----------------------------------------------------------------
def get_persistent_storage_service(state, sservice_group="default") :
    """return the url for the persistent storage service specified in the service group; the
    persistent storage service will be included in the list of replicas
    """
    sservice_info = pgroups.get_group_info('sservice', sservice_group)
    return sservice_info.persistent

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_create(pscript.script_command_base) :
    name = "create"
    help = "Create a new storage service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the storage service group', type=str, default='default')
        subparser.add_argument('--url', help='URLs for storage services', type=str, nargs='+', default=[])
        subparser.add_argument('--name', help='Names for storage services', type=str, nargs='+', default=[])
        subparser.add_argument('--replicas', help='Number of provable replicas', type=int)
        subparser.add_argument('--duration', help='Minimum acceptable duration', type=int)
        subparser.add_argument('--persistent', help='URL for a persistent storage service', type=str)

    @classmethod
    def invoke(cls, state, bindings, group, replicas=None, duration=None, persistent=None, name=[], url=[], **kwargs) :
        service_urls = url + pservice.expand_service_names('sservice', name)
        service_urls = list(set(service_urls))   # remove duplicates

        params = {}
        params['replicas'] = replicas or pconfig.shared_configuration(['Replication', 'NumProvableReplicas'], 2)
        params['duration'] = duration or pconfig.shared_configuration(['Replication', 'Duration'], 120)
        if persistent :
            params['persistent'] = persistent

        pgroups.add_group('sservice', group, service_urls, **params)
        return list(service_urls)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_create_from_site(pscript.script_command_base) :
    """Create service group from a service site file

    Build a service group for all of the provisioning services listed in
    a site file (typically generated as site.toml. One group will be
    created that includes all of the listed services.
    """

    name = "create_from_site"
    help = "Import service group from a services site file"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help="Name of the group to create", required=True, type=str)
        subparser.add_argument('--file', help="Name of the site file", dest='filename', required=True, type=str)
        subparser.add_argument('--replicas', help='Number of provable replicas', type=int)
        subparser.add_argument('--duration', help='Minimum acceptable duration', type=int)
        subparser.add_argument('--persistent', help='URL for a persistent storage service', type=str)

    @classmethod
    def invoke(cls, state, bindings, group, filename, replicas=None, duration=None, persistent=None, **kwargs) :
        search_path = state.get(['Client', 'SearchPath'], ['.', './etc/'])
        filename = putils.find_file_in_path(filename, search_path)
        services = pconfig.parse_configuration_file(filename, bindings)

        service_urls = []
        for s in services.get('StorageService') :
            service_urls.append(s['URL'])
        service_urls = list(set(service_urls))   # remove duplicates

        params = {}
        params['replicas'] = replicas or pconfig.shared_configuration(['Replication', 'NumProvableReplicas'], 2)
        params['duration'] = duration or pconfig.shared_configuration(['Replication', 'Duration'], 120)
        if persistent :
            params['persistent'] = persistent

        pgroups.add_group('sservice', group, service_urls, **params)
        return list(service_urls)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_delete(pscript.script_command_base) :
    name = "delete"
    help = "Delete a storage service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the storage service group', type=str, default='default')

    @classmethod
    def invoke(cls, state, bindings, group, **kwargs) :
        pgroups.remove_group('sservice', group)
        return True


## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_add(pscript.script_command_base) :
    name = "add"
    help = "Add a list of URLs to a storage service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the storage service group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for storage services', type=str, nargs='+', required=True)
        subparser.add_argument('--name', help='Names for storage services', type=str, nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, group, name=[], url=[], **kwargs) :
        # this verifies that the group exists, will throw exception if the group does not exist
        group_info = pgroups.get_group_info('sservice', group)

        params = {}
        params['replicas'] = group_info.replicas
        params['duration'] = group_info.duration
        params['persistent'] = group_info.persistent

        service_urls = group_info.service_urls + url + pservice.expand_service_names('sservice', name)
        service_urls = list(set(service_urls))   # remove duplicates

        pgroups.add_group('sservice', group, service_urls, **params)
        return list(service_urls)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_remove(pscript.script_command_base) :
    name = "remove"
    help = "Remove a list of URLs from a storage service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the storage service group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for storage services', type=str, nargs='+', required=True)
        subparser.add_argument('--name', help='Names for storage services', type=str, nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, group, name=[], url=[], **kwargs) :
        # this verifies that the group exists, will throw exception if the group does not exist
        group_info = pgroups.get_group_info('sservice', group)

        params = {}
        params['replicas'] = group_info.replicas
        params['duration'] = group_info.duration
        params['persistent'] = group_info.persistent

        service_urls = group_info.service_urls
        map(lambda u : u in service_urls and service_urls.remove(u), url)
        map(lambda u : u in service_urls and service_urls.remove(u), pservice.expand_service_names('sservice', name))
        service_urls = list(set(service_urls))   # remove duplicates

        pgroups.add_group('sservice', group, service_urls, **params)
        return list(service_urls)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_set(pscript.script_command_base) :
    name = "set"
    help = "Set the list of URLs for a storage service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the storage group', type=str, default="default")
        subparser.add_argument('--replicas', help='Number of provable replicas', type=int, required=False)
        subparser.add_argument('--duration', help='Minimum acceptable duration', type=int, required=False)
        subparser.add_argument('--persistent', help='URL for a persistent storage service', type=str, required=False)
        subparser.add_argument('--url', help='URLs for storage services', type=str, nargs='+', required=False)
        subparser.add_argument('--name', help='Names for storage services', type=str, nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, group, replicas=None, duration=None, persistent=None, name=[], url=[], **kwargs) :
        # this verifies that the group exists, will throw exception if the group does not exist
        group_info = pgroups.get_group_info('sservice', group)

        params = {}
        params['replicas'] = replicas or group_info.replicas
        params['duration'] = duration or group_info.duration
        params['persistent'] = persistent or group_info.persistent

        if url or name :
            service_urls = url + pservice.expand_service_names('sservice', name)
            service_urls = list(set(service_urls))   # remove duplicates
        else :
            service_urls = group_info.service_urls

        pgroups.add_group('sservice', group, service_urls, **params)
        return list(service_urls)

## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__subcommands__ = [
    script_command_create,
    script_command_create_from_site,
    script_command_delete,
    script_command_add,
    script_command_remove,
    script_command_set,
]
do_sservice = pscript.create_shell_command('sservice', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'sservice', do_sservice)
