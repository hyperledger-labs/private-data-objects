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
import random

import logging
logger = logging.getLogger(__name__)

from pdo.service_client.enclave import EnclaveServiceClient
import pdo.service_client.service_data.eservice as eservice_db

__all__ = ['command_eservice', 'get_eservice', 'get_eservice_list']

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def __expand_eservice_names__(names) :
    result = set()
    if names :
        for name in names :
            eservice_info = eservice_db.get_by_name(name)
            if eservice_info is None :
                raise Exception('unknown eservice name {0}'.format(name))
            result.add(eservice_info.url)

    return result

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_eservice(state, bindings, pargs) :
    """controller command to manage the list of enclave services
    """
    subcommands = ['add', 'remove', 'set', 'list', 'create-group', 'use' ]

    parser = argparse.ArgumentParser(prog='eservice')
    parser.add_argument('--group', help='Name of the eservice group', type=str, default="default")

    subparsers = parser.add_subparsers(dest='command')

    subparser = subparsers.add_parser('add')
    subparser.add_argument('--url', help='URLs for enclave services', type=str, nargs='+')
    subparser.add_argument('--name', help='EService DB name for enclave services', type=str, nargs='+')

    subparser = subparsers.add_parser('remove')
    subparser.add_argument('--url', help='URLs for enclave services', type=str, nargs='+')
    subparser.add_argument('--name', help='EService DB name for enclave services', type=str, nargs='+')

    subparser = subparsers.add_parser('set')
    subparser.add_argument('--url', help='URLs for enclave services', type=str, nargs='+')
    subparser.add_argument('--name', help='EService DB name for enclave services', type=str, nargs='+')

    subparser = subparsers.add_parser('list')

    subparser = subparsers.add_parser('use')
    eservice_group = subparser.add_mutually_exclusive_group(required=True)
    eservice_group.add_argument('--url', help='URLs for enclave services', type=str)
    eservice_group.add_argument('--name', help='EService DB name for enclave services', type=str)
    eservice_group.add_argument('--random', help='No preferred enclave service', action='store_true')

    options = parser.parse_args(pargs)

    if options.command == 'add' :
        services = set(state.get(['Service', 'EnclaveServiceGroups', options.group, 'urls'], []))
        if options.url :
            services = services.union(options.url)
        if options.name :
            services = services.union(__expand_eservice_names__(options.name))
        state.set(['Service', 'EnclaveServiceGroups', options.group, 'urls'], list(services))
        return

    if options.command == 'remove' :
        services = set(state.get(['Service', 'EnclaveServiceGroups', options.group, 'urls'], []))
        if options.url :
            services = services.difference(options.url)
        if options.name :
            services = services.difference(__expand_eservice_names__(options.name))
        state.set(['Service', 'EnclaveServiceGroups', options.group, 'urls'], list(services))
        return

    if options.command == 'set' :
        services = set()
        if options.url :
            services = services.union(options.url)
        if options.name :
            services = services.union(__expand_eservice_names__(options.name))
        state.set(['Service', 'EnclaveServiceGroups', options.group, 'urls'], list(services))
        return

    if options.command == 'use' :
        if options.random :
            state.set(['Service', 'EnclaveServiceGroups', options.group, 'preferred'], 'random')
            return

        service_url = None
        if options.url :
            service_url = options.url
        if options.name :
            service_info = eservice_db.get_by_name(options.name)
            if service_info is None :
                raise Exception('unknown eservice name; %s', options.name)
            service_url = service_info.url

        services = state.get(['Service', 'EnclaveServiceGroups', options.group, 'urls'], [])
        if service_url in services :
            state.set(['Service', 'EnclaveServiceGroups', options.group, 'preferred'], service_url)
        else :
            raise Exception('preferred URL not in the service group')
        return

    if options.command == 'list' :
        preferred = state.get(['Service', 'EnclaveServiceGroups', options.group, 'preferred'], 'random')
        services = state.get(['Service', 'EnclaveServiceGroups', options.group, 'urls'], [])
        print("preferred: {0}".format(preferred))
        for service in services :
            print(service)
        return

    raise Exception('unknown subcommand')

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def get_eservice(state, eservice_url="default", eservice_group="default") :
    """create an enclave client for the preferred enclave service; assumes
    exception handling by the calling procedure
    """

    if eservice_url is 'default' or eservice_url is None :
        eservice_url = state.get(['Service', 'EnclaveServiceGroups', eservice_group, 'preferred'], 'random')

    if eservice_url == 'random' :
        eservice_url = random.choice(state.get(['Service', 'EnclaveServiceGroups', eservice_group, 'urls'], []))

    if eservice_url is None :
        raise Exception('no enclave service specified')

    logger.debug('get client for %s', eservice_url)
    return EnclaveServiceClient(eservice_url)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def get_eservice_list(state, eservice_group="default") :
    """create a list of eservice clients from the specified eservice group; assumes
    exception handling by the calling procedure
    """
    eservice_url_list = state.get(['Service', 'EnclaveServiceGroups', eservice_group, 'urls'], [])
    eservice_client_list = []
    for eservice_url in eservice_url_list :
        eservice_client_list.append(EnclaveServiceClient(eservice_url))

    return eservice_client_list
