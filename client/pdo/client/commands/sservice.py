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

import pdo.client.builder.shell as pshell
import pdo.client.builder.script as pscript

logger = logging.getLogger(__name__)

__all__ = [
    'get_replica_list',
    'get_replica_count',
    'get_replica_duration',
    'get_persistent_storage_service',
    'script_command_add',
    'script_command_remove',
    'script_command_set',
    'script_command_list',
    'do_sservice',
    'load_commands',
]

## -----------------------------------------------------------------
def get_replica_list(state, sservice_group="default") :
    """create a list of urls for the services from the specified sservice group; assumes
    exception handling by the calling procedure
    """
    sservice_url_list = set(state.get(['Service', 'StorageServiceGroups', sservice_group, 'urls'], []))
    persistent_service_url = get_persistent_storage_service(state, sservice_group)
    if persistent_service_url :
        sservice_url_list.add(persistent_service_url)

    return list(sservice_url_list)

## -----------------------------------------------------------------
def get_replica_count(state, sservice_group="default") :
    """return the replica count associated with the specified service group; defaults
    to the configuration for Replication
    """
    replicas = state.get(['Service', 'StorageServiceGroups', sservice_group, 'replicas'])
    if not replicas :
        replicas = state.get(['Replication', 'NumProvableReplicas'], 2)

    return replicas

## -----------------------------------------------------------------
def get_replica_duration(state, sservice_group="default") :
    """return the minimum duration sservices are expected to hold a replica; this is
    pulled from the specified service group; defaults to the configuration for Replication
    """
    duration = state.get(['Service', 'StorageServiceGroups', sservice_group, 'duration'])
    if not duration :
        duration = state.get(['Replication', 'Duration'], 120)

    return duration

## -----------------------------------------------------------------
def get_persistent_storage_service(state, sservice_group="default") :
    """return the url for the persistent storage service specified in the service group; the
    persistent storage service will be included in the list of replicas
    """
    persistent_service_url = state.get(['Service', 'StorageServiceGroups', sservice_group, 'persistent'])
    if not persistent_service_url :
        persistent_service_url = state.get(['Replication', 'PersistentStorage'])

    return persistent_service_url

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_add(pscript.script_command_base) :
    name = "add"
    help = "Add a list of URLs to a storage service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the sservice group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for storage services', type=str, nargs='+', required=True)

    @classmethod
    def invoke(cls, state, bindings, group, url, **kwargs) :
        services = set(state.get(['Service', 'StorageServiceGroups', group, 'urls'], []))
        services = services.union(url)
        state.set(['Service', 'StorageServiceGroups', group, 'urls'], list(services))
        return list(services)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_remove(pscript.script_command_base) :
    name = "remove"
    help = "Remove a list of URLs from a storage service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the pservice group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for storage services', type=str, nargs='+', required=True)

    @classmethod
    def invoke(cls, state, bindings, group, url, **kwargs) :
        services = set(state.get(['Service', 'StorageServiceGroups', group, 'urls'], []))
        services = services.difference(url)
        state.set(['Service', 'StorageServiceGroups', group, 'urls'], list(services))

        return list(services)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_set(pscript.script_command_base) :
    name = "set"
    help = "Set the list of URLs for a storage service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the sservice group', type=str, default="default")
        subparser.add_argument('--replicas', help='Number of provable replicas', type=int, required=False)
        subparser.add_argument('--duration', help='Minimum acceptable duration', type=int, required=False)
        subparser.add_argument('--persistent', help='URL for a persistent storage service', type=str, required=False)
        subparser.add_argument('--url', help='URLs for storage services', type=str, nargs='+', required=False)

    @classmethod
    def invoke(cls, state, bindings, group, replicas=None, duration=None, persistent=None, url=[], **kwargs) :
        if replicas :
            state.set(['Service', 'StorageServiceGroups', group, 'replicas'], replicas)
        if duration :
            state.set(['Service', 'StorageServiceGroups', group, 'duration'], duration)
        if persistent :
            state.set(['Service', 'StorageServiceGroups', group, 'persistent'], persistent)
        if url :
            state.set(['Service', 'StorageServiceGroups', group, 'urls'], url)

        return state.get(['Service', 'StorageServiceGroups', group],{})

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_list(pscript.script_command_base) :
    name = "list"
    help = "List service URLs associated with a storage service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the storage sservice group', type=str, default="default")

    @classmethod
    def invoke(cls, state, bindings, group, **kwargs) :
        count = get_replica_count(state, options.group)
        duration = get_replica_duration(state, options.group)
        persistent = get_persistent_storage_service(state, options.group)
        services = get_replica_list(state, options.group)

        cls.display_highlight("persistent storage: {0}".format(persistent))
        cls.display_highlight("minimum replicas: {0}".format(count))
        cls.display_highlight("minimum duration: {0}".format(duration))
        for service in services :
            cls.display(service)

        return services

## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__subcommands__ = [
    script_command_add,
    script_command_remove,
    script_command_set,
    script_command_list,
]
do_sservice = pscript.create_shell_command('sservice', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'sservice', do_sservice)
