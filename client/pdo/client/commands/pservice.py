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
from pdo.service_client.provisioning import ProvisioningServiceClient

logger = logging.getLogger(__name__)

__all__ = [
    'get_pservice_list',
    'script_command_add',
    'script_command_remove',
    'script_command_set',
    'script_command_list',
    'do_pservice',
    'load_commands',
]

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

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_add(pscript.script_command_base) :
    name = "add"
    help = "Add a list of URLs to a pservice service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the pservice group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for provisioning services', type=str, nargs='+', required=True)

    @classmethod
    def invoke(cls, state, bindings, group, url, **kwargs) :
        services = set(state.get(['Service', 'ProvisioningServiceGroups', group, 'urls'], []))
        services = services.union(url)
        state.set(['Service', 'ProvisioningServiceGroups', group, 'urls'], list(services))
        return list(services)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_remove(pscript.script_command_base) :
    name = "remove"
    help = "Remove a list of URLs from a provisioning service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the pservice group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for provisioning services', type=str, nargs='+', required=True)

    @classmethod
    def invoke(cls, state, bindings, group, url, **kwargs) :
        services = set(state.get(['Service', 'ProvisioningServiceGroups', group, 'urls'], []))
        services = services.difference(url)
        state.set(['Service', 'ProvisioningServiceGroups', group, 'urls'], list(services))
        return list(services)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_set(pscript.script_command_base) :
    name = "set"
    help = "Set the list of URLs for a provisioning service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the pservice group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for provisioning services', type=str, nargs='+', required=True)

    @classmethod
    def invoke(cls, state, bindings, group, url, **kwargs) :
        services = set(url)
        state.set(['Service', 'ProvisioningServiceGroups', group, 'urls'], list(services))
        return list(services)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_list(pscript.script_command_base) :
    name = "list"
    help = "List service URLs associated with a pservice group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the pservice group', type=str, default="default")

    @classmethod
    def invoke(cls, state, bindings, group, **kwargs) :
        services = state.get(['Service', 'ProvisioningServiceGroups', group, 'urls'], [])
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
do_pservice = pscript.create_shell_command('pservice', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'pservice', do_pservice)
