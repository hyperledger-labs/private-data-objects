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

__all__ = ['command_pservice']

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_pservice(state, bindings, pargs) :
    """controller command to manage the list of provisioning services
    """
    subcommands = ['add', 'remove', 'set', 'info', 'list']

    parser = argparse.ArgumentParser(prog='pservice')
    subparsers = parser.add_subparsers(dest='command')

    add_parser = subparsers.add_parser('add')
    add_parser.add_argument('--url', help='URLs for the provisioning service', type=str, nargs='+', required=True)

    remove_parser = subparsers.add_parser('remove')
    remove_parser.add_argument('--url', help='URLs for the provisioning service', type=str, nargs='+', required=True)

    set_parser = subparsers.add_parser('set')
    set_parser.add_argument('--url', help='URLs for the provisioning service', type=str, nargs='+', required=True)

    info_parser = subparsers.add_parser('info')
    info_parser.add_argument('--url', help='URLs for the provisioning service', type=str, nargs='+')

    list_parser = subparsers.add_parser('list')

    options = parser.parse_args(pargs)

    if options.command == 'add' :
        services = set(state.get(['Service', 'ProvisioningServiceURLs'], []))
        services = services.union(options.url)
        state.set(['Service', 'ProvisioningServiceURLs'], list(services))
        return

    if options.command == 'remove' :
        services = set(state.get(['Service', 'ProvisioningServiceURLs'], []))
        services = services.difference(options.url)
        state.set(['Service', 'ProvisioningServiceURLs'], list(services))
        return

    if options.command == 'set' :
        state.set(['Service', 'ProvisioningServiceURLs'], options.url)
        return

    if options.command == 'info' :
        services = state.get(['Service', 'ProvisioningServiceURLs'], [])
        if options.url :
            services = options.url

        for url in services :
            try :
                client = ProvisioningServiceClient(url)
                print("{0} --> {1}".format(url, client.verifying_key))
            except :
                print('unable to retreive information from {0}'.format(url))
        return

    if options.command == 'list' :
        services = set(state.get(['Service', 'ProvisioningServiceURLs'], []))
        for service in services :
            print(service)
        return

    raise Exception('unknown subcommand')
