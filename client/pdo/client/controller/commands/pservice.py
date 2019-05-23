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

from pdo.service_client.provisioning import ProvisioningServiceClient

__all__ = ['command_pservice', 'get_pservice_list']

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_pservice(state, bindings, pargs) :
    """controller command to manage the list of enclave services
    """
    subcommands = ['add', 'remove', 'set', 'list', 'create-group', 'use' ]

    parser = argparse.ArgumentParser(prog='pservice')
    parser.add_argument('--group', help='Name of the pservice group', type=str, default="default")

    subparsers = parser.add_subparsers(dest='command')

    add_parser = subparsers.add_parser('add')
    add_parser.add_argument('--url', help='URLs for provisioning services', type=str, nargs='+', required=True)

    remove_parser = subparsers.add_parser('remove')
    remove_parser.add_argument('--url', help='URLs for provisioning services', type=str, nargs='+', required=True)

    set_parser = subparsers.add_parser('set')
    set_parser.add_argument('--url', help='URLs for provisioning services', type=str, nargs='+', required=True)

    list_parser = subparsers.add_parser('list')

    options = parser.parse_args(pargs)

    if options.command == 'add' :
        services = set(state.get(['Service', 'ProvisioningServiceGroups', options.group, 'urls'], []))
        services = services.union(options.url)
        state.set(['Service', 'ProvisioningServiceGroups', options.group, 'urls'], list(services))
        return

    if options.command == 'remove' :
        services = set(state.get(['Service', 'ProvisioningServiceGroups', options.group, 'urls'], []))
        services = services.difference(options.url)
        state.set(['Service', 'ProvisioningServiceGroups', options.group, 'urls'], list(services))
        return

    if options.command == 'set' :
        state.set(['Service', 'ProvisioningServiceGroups', options.group, 'urls'], options.url)
        return

    if options.command == 'list' :
        preferred = state.get(['Service', 'ProvisioningServiceGroups', options.group, 'preferred'], '')
        services = state.get(['Service', 'ProvisioningServiceGroups', options.group, 'urls'], [])
        print("preferred: {0}".format(preferred))
        for service in services :
            print(service)
        return

    raise Exception('unknown subcommand')

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def get_pservice_list(state, pservice_group="default") :
    """create a list of pservice clients from the specified pservice group; assumes
    exception handling by the calling procedure
    """
    pservice_url_list = state.get(['Service', 'ProvisioningServiceGroups', pservice_group, 'urls'], [])
    pservice_client_list = []
    for pservice_url in pservice_url_list :
        pservice_client_list.append(ProvisioningServiceClient(pservice_url))

    return pservice_client_list
