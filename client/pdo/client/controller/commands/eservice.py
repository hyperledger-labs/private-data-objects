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
import sys
import os
import json


logger = logging.getLogger(__name__)

from pdo.service_client.enclave import EnclaveServiceClient


__all__ = ['command_eservice']

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_eservice(state, bindings, pargs) :
    """controller command to manage the list of enclave services
    """
    subcommands = ['add', 'remove', 'set', 'use', 'info', 'list', 'udpatedb']

    parser = argparse.ArgumentParser(prog='eservice')
    subparsers = parser.add_subparsers(dest='command')
    add_parser = subparsers.add_parser('add')
    add_parser.add_argument('--url', help='URLs for the enclave service', type=str, nargs='+', required=True)

    remove_parser = subparsers.add_parser('remove')
    remove_parser.add_argument('--url', help='URLs for the enclave service', type=str, nargs='+', required=True)

    set_parser = subparsers.add_parser('set')
    set_parser.add_argument('--url', help='URLs for the enclave service', type=str, nargs='+', required=True)

    info_parser = subparsers.add_parser('use')
    info_parser.add_argument('--url', help='URLs for the enclave service', type=str, required=True)

    info_parser = subparsers.add_parser('info')
    info_parser.add_argument('--url', help='URLs for the enclave service', type=str, nargs='+')

    list_parser = subparsers.add_parser('list')

    options = parser.parse_args(pargs)

    if options.command == 'add' :
        services = set(state.get(['Service', 'EnclaveServiceURLs'], []))
        services = services.union(options.url)
        state.set(['Service', 'EnclaveServiceURLs'], list(services))
        return

    if options.command == 'remove' :
        services = set(state.get(['Service', 'EnclaveServiceURLs'], []))
        services = services.difference(options.url)
        state.set(['Service', 'EnclaveServiceURLs'], list(services))
        return

    if options.command == 'set' :
        state.set(['Service', 'EnclaveServiceURLs'], options.url)
        return

    if options.command == 'use' :
        state.set(['Service', 'PreferredEnclaveService'], options.url)
        return

    if options.command == 'info' :
        services = state.get(['Service', 'EnclaveServiceURLs'])
        if options.url :
            services = options.url

        for url in services :
            try :
                client = EnclaveServiceClient(url)
                print("{0} --> {1}".format(url, client.verifying_key))
            except :
                print('unable to retreive information from {0}'.format(url))
        return

    if options.command == 'list' :
        services = set(state.get(['Service', 'EnclaveServiceURLs'], []))
        for service in services :
            print(service)

        return

    raise Exception('unknown subcommand')

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def get_enclave_service(state=None, enclave_url=None) :
    """create an enclave client for the preferred enclave service; assumes
    exception handling by the calling procedure
    """
    if enclave_url is None :
        enclave_url = state.get(['Service', 'PreferredEnclaveService'], None)
        if enclave_url is None :
            enclave_url = random.choice(state.get(['Service', 'EnclaveServiceURLs'], []))

    if enclave_url is None :
        raise Exception('no enclave service specified')

    return EnclaveServiceClient(enclave_url)
