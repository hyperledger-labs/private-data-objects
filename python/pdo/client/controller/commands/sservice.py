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

logger = logging.getLogger(__name__)

__all__ = [
    'command_sservice',
    'get_replica_list',
    'get_replica_count',
    'get_replica_duration',
    'get_persistent_storage_service'
]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_sservice(state, bindings, pargs) :
    """controller command to manage the list of enclave services
    """
    subcommands = ['add', 'remove', 'set', 'list' ]

    parser = argparse.ArgumentParser(prog='sservice')
    parser.add_argument('--group', help='Name of the sservice group', type=str, default="default")

    subparsers = parser.add_subparsers(dest='command')

    add_parser = subparsers.add_parser('add')
    add_parser.add_argument('--url', help='URLs for storage services', type=str, nargs='+', required=True)

    remove_parser = subparsers.add_parser('remove')
    remove_parser.add_argument('--url', help='URLs for storage services', type=str, nargs='+', required=True)

    set_parser = subparsers.add_parser('set')
    set_parser.add_argument('--replicas', help='Number of provable replicas', type=int, required=False)
    set_parser.add_argument('--duration', help='Minimum acceptable duration', type=int, required=False)
    set_parser.add_argument('--persistent', help='URL for a persistent storage service', type=str, required=False)
    set_parser.add_argument('--url', help='URLs for storage services', type=str, nargs='+', required=False)

    list_parser = subparsers.add_parser('list')

    options = parser.parse_args(pargs)

    if options.command == 'add' :
        services = set(state.get(['Service', 'StorageServiceGroups', options.group, 'urls'], []))
        services = services.union(options.url)
        state.set(['Service', 'StorageServiceGroups', options.group, 'urls'], list(services))
        return

    if options.command == 'remove' :
        services = set(state.get(['Service', 'StorageServiceGroups', options.group, 'urls'], []))
        services = services.difference(options.url)
        state.set(['Service', 'StorageServiceGroups', options.group, 'urls'], list(services))
        return

    if options.command == 'set' :
        if options.replicas :
            state.set(['Service', 'StorageServiceGroups', options.group, 'replicas'], options.replicas)
        if options.duration :
            state.set(['Service', 'StorageServiceGroups', options.group, 'duration'], options.duration)
        if options.persistent :
            state.set(['Service', 'StorageServiceGroups', options.group, 'persistent'], options.persistent)
        if options.url :
            state.set(['Service', 'StorageServiceGroups', options.group, 'urls'], options.url)
        return

    if options.command == 'list' :
        count = get_replica_count(state, options.group)
        duration = get_replica_duration(state, options.group)
        persistent = get_persistent_storage_service(state, options.group)
        services = get_replica_list(state, options.group)

        print("persistent storage: {0}".format(persistent))
        print("minimum replicas: {0}".format(count))
        print("minimum duration: {0}".format(duration))
        for service in services :
            print(service)
        return

    raise Exception('unknown subcommand')

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
