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

from pdo.service_client.provisioning import ProvisioningServiceClient

logger = logging.getLogger(__name__)

__all__ = [
    'get_pservice_list',
    'script_command_create',
    'script_command_create_from_site',
    'script_command_delete',
    'script_command_add',
    'script_command_remove',
    'script_command_set',
    'do_pservice',
    'load_commands',
]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def get_pservice_list(state, pservice_group="default") :
    """create a list of pservice clients from the specified pservice group; assumes
    exception handling by the calling procedure
    """

    group_info = pgroups.get_group_info('pservice', pservice_group)

    pservice_client_list = []
    for pservice_url in group_info.service_urls :
        pservice_client_list.append(ProvisioningServiceClient(pservice_url))

    return pservice_client_list

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_create(pscript.script_command_base) :
    name = "create"
    help = "Create a new provisionin service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the provisioning service group', type=str, default='default')
        subparser.add_argument('--url', help='URLs for provisioning services', type=str, nargs='+', default=[])
        subparser.add_argument('--name', help='Names for provisioning services', type=str, nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, group, name=[], url=[], **kwargs) :
        service_urls = url + pservice.expand_service_names('pservice', name)
        service_urls = list(set(service_urls))   # remove duplicates

        pgroups.add_group('pservice', group, service_urls)
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

    @classmethod
    def invoke(cls, state, bindings, group, filename, **kwargs) :
        search_path = state.get(['Client', 'SearchPath'], ['.', './etc/'])
        filename = putils.find_file_in_path(filename, search_path)
        services = pconfig.parse_configuration_file(filename, bindings)

        service_urls = []
        for s in services.get('ProvisioningService') :
            service_urls.append(s['URL'])
        service_urls = list(set(service_urls))   # remove duplicates

        pgroups.add_group('pservice', group, service_urls)
        return True

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_delete(pscript.script_command_base) :
    name = "delete"
    help = "Delete a provisioning service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the provisioning service group', type=str, default='default')

    @classmethod
    def invoke(cls, state, bindings, group, **kwargs) :

        pgroups.remove_group('pservice', group)
        return True

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_add(pscript.script_command_base) :
    name = "add"
    help = "Add a list of URLs to a provisioning service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the provisioning service group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for provisioning services', type=str, nargs='+', default=[])
        subparser.add_argument('--name', help='Names for provisioning services', type=str, nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, group, name = [], url = [], **kwargs) :
        # this verifies that the group exists, will throw exception if the group does not exist
        group_info = pgroups.get_group_info('pservice', group)

        service_urls = group_info.service_urls + url + pservice.expand_service_names('pservice', name)
        service_urls = list(set(service_urls))   # remove duplicates

        pgroups.add_group('pservice', group, service_urls)
        return list(service_urls)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_remove(pscript.script_command_base) :
    name = "remove"
    help = "Remove a list of URLs from a provisioning service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the provisioning service group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for provisioning services', type=str, nargs='+', default=[])
        subparser.add_argument('--name', help='Names for provisioning services', type=str, nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, group, name=[], url=[], **kwargs) :
        # this verifies that the group exists, will throw exception if the group does not exist
        group_info = pgroups.get_group_info('pservice', group)

        service_urls = group_info.service_urls
        map(lambda u : u in service_urls and service_urls.remove(u), url)
        map(lambda u : u in service_urls and service_urls.remove(u), pservice.expand_service_names('pservice', name))
        service_urls = list(set(service_urls))   # remove duplicates

        pgroups.add_group('pservice', group, service_urls)
        return list(service_urls)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_set(pscript.script_command_base) :
    name = "set"
    help = "Set the list of URLs for a provisioning service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the provisioning service group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for provisioning services', type=str, nargs='+', default=[])
        subparser.add_argument('--name', help='Names for provisioning services', type=str, nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, group, name=[], url=[], **kwargs) :
        # this verifies that the group exists, will throw exception if the group does not exist
        group_info = pgroups.get_group_info('pservice', group)

        service_urls = list(set(url))   # remove duplicates
        pgroups.add_group('pservice', group, service_urls)
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
do_pservice = pscript.create_shell_command('pservice', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'pservice', do_pservice)
