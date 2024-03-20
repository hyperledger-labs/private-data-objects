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
import random

import pdo.common.config as pconfig
import pdo.common.utility as putils

import pdo.client.builder.shell as pshell
import pdo.client.builder.script as pscript
import pdo.client.commands.contract as pcontract
import pdo.client.commands.service_groups as pgroups
import pdo.client.commands.service_db as pservice

from pdo.service_client.service_data.service_data import ServiceDatabaseManager as service_data


logger = logging.getLogger(__name__)

__all__ = [
    'get_eservice',
    'get_eservice_from_contract',
    'get_eservice_list',
    'script_command_create',
    'script_command_create_from_site',
    'script_command_delete',
    'script_command_add',
    'script_command_remove',
    'script_command_set',
    'script_command_use',
    'do_eservice',
    'load_commands',
]

def __get_by_name__(name) :
    return service_data.local_service_manager.get_by_name(name, 'eservice')

def __get_by_identity__(identity) :
    return service_data.local_service_manager.get_by_identity(identity, 'eservice')

def __get_by_url__(url) :
    return service_data.local_service_manager.get_by_url(url, 'eservice')

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def get_eservice(state, eservice_url="default", eservice_group="default") :
    """create an enclave client for the preferred enclave service; assumes
    exception handling by the calling procedure
    """

    group_info = pgroups.get_group_info('eservice', eservice_group)

    if eservice_url == 'default' or eservice_url is None :
        eservice_url = group_info.preferred or 'random'

    if eservice_url == 'random' :
        eservice_url = random.choice(group_info.service_urls)

    if eservice_url is None :
        raise Exception('no enclave service specified')

    logger.debug('get client for %s', eservice_url)
    return __get_by_url__(eservice_url).client()

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def get_eservice_from_contract(state, save_file, eservice_url=None, **kwargs) :
    """retrieve an eservice client for the specified enclave within the context
    of the contract; that is, interpret keywords/names for the eservice_url using
    metadata from the contract (e.g. preferred enclave) and make sure that the
    result enclave client is actually provisioned for the contract.
    """
    try :
        contract = pcontract.get_contract(state, save_file)
    except Exception as e :
        raise Exception('unable to load the contract')

    if eservice_url is None :
        eservice_url = 'preferred'

    # if the url is specified as a URL then check the cache and create the client
    if putils.valid_service_url(eservice_url) :
        try :
            eservice_client = __get_by_url__(eservice_url).client()
        except Exception as e :
            raise Exception('unable to connect to enclave service; {0}'.format(str(e)))

    # if the url is a key value, then process accordingly, this can be the
    # keywords "preferred" and "random" or a name that has been stored in the
    # eservice database
    else :
        if eservice_url == 'preferred' :
            enclave_id = contract.extra_data.get('preferred-enclave', random.choice(contract.provisioned_enclaves))
            eservice_info = __get_by_identity__(enclave_id)
        elif eservice_url == 'random' :
            enclave_id = random.choice(contract.provisioned_enclaves)
            eservice_info = __get_by_identity__(enclave_id)
        else :
            eservice_info = __get_by_name__(eservice_url)

        if eservice_info is None :
            raise Exception('attempt to use an unknown enclave; %s', eservice_url)

        try :
            eservice_client = eservice_info.client()
        except Exception as e :
            raise Exception('unable to connect to enclave service; {0}'.format(str(e)))

    # sanity check: make sure the selected enclave is actually included in the contract
    if eservice_client.enclave_id not in contract.provisioned_enclaves :
        raise Exception('requested enclave not provisioned for the contract; %s', eservice_url)

    return eservice_client

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def get_eservice_list(state, eservice_group="default") :
    """create a list of eservice clients from the specified eservice group; assumes
    exception handling by the calling procedure
    """

    group_info = pgroups.get_group_info('eservice', eservice_group)
    eservice_url_list = group_info.service_urls
    eservice_client_list = []
    for eservice_url in eservice_url_list :
        eservice_client_list.append(__get_by_url__(eservice_url).client())

    return eservice_client_list

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_create(pscript.script_command_base) :
    name = "create"
    help = "Create a new enclave service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the eservice group', type=str, default='default')
        subparser.add_argument('--url', help='URLs for enclave services', type=str, nargs='+', default=[])
        subparser.add_argument('--name', help='EService DB names for enclave services', type=str, nargs='+', default=[])
        subparser.add_argument('--preferred', help='URL for preferred enclave service', type=str, default='random')

    @classmethod
    def invoke(cls, state, bindings, group, url=[], name=[], preferred='random', **kwargs) :
        service_urls = url + pservice.expand_service_names('eservice', name)
        service_urls = list(set(service_urls))   # remove duplicates

        pgroups.add_group('eservice', group, service_urls, preferred=preferred)
        return list(service_urls)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_create_from_site(pscript.script_command_base) :
    """Create service group from a service site file

    Build a service group for all of the enclave services listed in
    a site file (typically generated as site.toml. One group will be
    created that includes all of the listed services.
    """

    name = "create_from_site"
    help = "Import service group from a services site file"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help="Name of the group to create", required=True, type=str)
        subparser.add_argument('--file', help="Name of the site file", dest='filename', required=True, type=str)
        subparser.add_argument('--preferred', help='URL for preferred enclave service', type=str, default='random')
    @classmethod
    def invoke(cls, state, bindings, group, filename, preferred='random', **kwargs) :
        search_path = state.get(['Client', 'SearchPath'], ['.', './etc/'])
        filename = putils.find_file_in_path(filename, search_path)
        services = pconfig.parse_configuration_file(filename, bindings)

        service_urls = []
        for s in services.get('EnclaveService') :
            service_urls.append(s['URL'])
        service_urls = list(set(service_urls))   # remove duplicates

        pgroups.add_group('eservice', group, service_urls, preferred=preferred)
        return True

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_delete(pscript.script_command_base) :
    name = "delete"
    help = "Delete an enclave service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the eservice group', type=str, default='default')

    @classmethod
    def invoke(cls, state, bindings, group, **kwargs) :

        pgroups.remove_group('eservice', group)
        return True

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_add(pscript.script_command_base) :
    name = "add"
    help = "Add enclave services to an eservice group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the eservice group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for enclave services', type=str, nargs='+', default=[])
        subparser.add_argument('--name', help='Names for enclave services', type=str, nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, group, url=[], name=[], **kwargs) :
        group_info = pgroups.get_group_info('eservice', group)

        service_urls = group_info.service_urls + url + pservice.expand_service_names('eservice', name)
        service_urls = list(set(service_urls))   # remove duplicates

        pgroups.add_group('eservice', group, service_urls, preferred=group_info.preferred)
        return list(service_urls)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_remove(pscript.script_command_base) :
    name = "remove"
    help = "Remove enclave services from an eservice group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the eservice group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for enclave services', type=str, nargs='+', default=[])
        subparser.add_argument('--name', help='EService DB names for enclave services', type=str, nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, group, url=[], name=[], **kwargs) :
        group_info = pgroups.get_group_info('eservice', group)
        service_urls = group_info.service_urls

        map(lambda u : u in service_urls and service_urls.remove(u), url)
        map(lambda u : u in service_urls and service_urls.remove(u), pservice.expand_service_name('eservice', name))
        service_urls = list(set(service_urls))   # remove duplicates

        pgroups.add_group('eservice', group, service_urls, preferred=group_info.preferred)
        return list(services)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_set(pscript.script_command_base) :
    name = "set"
    help = ""

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the eservice group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for enclave services', type=str, nargs='+', default=[])
        subparser.add_argument('--name', help='EService DB names for enclave services', type=str, nargs='+', default=[])

    @classmethod
    def invoke(cls, state, bindings, group, url=[], name=[], **kwargs) :
        group_info = pgroups.get_group_info('eservice', group)

        service_urls = url + pservice.expand_service_names('eservice', name)
        service_urls = list(set(service_urls))   # remove duplicates

        pgroups.add_group('eservice', group, service_urls, preferred=group_info.preferred)
        return list(services)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_use(pscript.script_command_base) :
    name = "use"
    help = "Set the preferred enclave service to use for this group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the eservice group', type=str, default="default")
        eservice_group = subparser.add_mutually_exclusive_group(required=True)
        eservice_group.add_argument('--random', help='No preferred enclave service', action='store_true')
        eservice_group.add_argument('--url', help='URL for enclave service', type=str)
        eservice_group.add_argument('--name', help='EService DB name for enclave services', type=str)

    @classmethod
    def invoke(cls, state, bindings, group, url=None, name=None, random=None, **kwargs) :
        group_info = pgroups.get_group_info('eservice', group)

        if random :
            pgroups.add_group('eservice', group, group_info.service_urls, preferred='random')
            return True

        service_url = None
        if url :
            service_url = url
        elif name :
            service_url = pservice.expand_service_name('eservice', name)

        if service_url not in group_info.service_urls :
            raise Exception('preferred URL not in the service group')

        pgroups.add_group('eservice', group, group_info.service_urls, preferred=service_url)
        return True

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
    script_command_use,
]
do_eservice = pscript.create_shell_command('eservice', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'eservice', do_eservice)
