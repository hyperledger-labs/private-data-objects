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

import pdo.client.builder.shell as pshell
import pdo.client.builder.script as pscript
import pdo.client.commands.contract as pcontract

from pdo.service_client.service_data.service_data import ServiceDatabaseManager as service_data
import pdo.common.utility as putils

logger = logging.getLogger(__name__)

__all__ = [
    'get_eservice',
    'get_eservice_from_contract',
    'get_eservice_list',
    'script_command_add',
    'script_command_remove',
    'script_command_set',
    'script_command_use',
    'script_command_list',
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

    if eservice_url == 'default' or eservice_url is None :
        eservice_url = state.get(['Service', 'EnclaveServiceGroups', eservice_group, 'preferred'], 'random')

    if eservice_url == 'random' :
        eservice_url = random.choice(state.get(['Service', 'EnclaveServiceGroups', eservice_group, 'urls'], []))

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
    eservice_url_list = state.get(['Service', 'EnclaveServiceGroups', eservice_group, 'urls'], [])
    eservice_client_list = []
    for eservice_url in eservice_url_list :
        eservice_client_list.append(__get_by_url__(eservice_url).client())

    return eservice_client_list

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def __expand_eservice_names__(names) :
    result = set()
    if names :
        for name in names :
            eservice_info = __get_by_name__(name)
            if eservice_info is None :
                raise Exception('unknown eservice name {0}'.format(name))
            result.add(eservice_info.service_url)

    return result

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_add(pscript.script_command_base) :
    name = "add"
    help = "Add enclave services to an eservice group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the eservice group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for enclave services', type=str, nargs='+')
        subparser.add_argument('--name', help='EService DB names for enclave services', type=str, nargs='+')

    @classmethod
    def invoke(cls, state, bindings, group, url=[], name=[], **kwargs) :
        services = set(state.get(['Service', 'EnclaveServiceGroups', group, 'urls'], []))
        if url :
            services = services.union(url)
        if name :
            services = services.union(__expand_eservice_names__(name))
        state.set(['Service', 'EnclaveServiceGroups', group, 'urls'], list(services))
        return list(services)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_remove(pscript.script_command_base) :
    name = "remove"
    help = "Remove enclave services from an eservice group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the eservice group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for enclave services', type=str, nargs='+')
        subparser.add_argument('--name', help='EService DB names for enclave services', type=str, nargs='+')

    @classmethod
    def invoke(cls, state, bindings, group, url=[], name=[], **kwargs) :
        services = set(state.get(['Service', 'EnclaveServiceGroups', group, 'urls'], []))
        if url :
            services = services.difference(url)
        if name :
            services = services.difference(__expand_eservice_names__(name))
        state.set(['Service', 'EnclaveServiceGroups', group, 'urls'], list(services))
        return list(services)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_set(pscript.script_command_base) :
    name = "set"
    help = ""

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the eservice group', type=str, default="default")
        subparser.add_argument('--url', help='URLs for enclave services', type=str, nargs='+')
        subparser.add_argument('--name', help='EService DB names for enclave services', type=str, nargs='+')

    @classmethod
    def invoke(cls, state, bindings, group, url=[], name=[], **kwargs) :
        services = set()
        if url :
            services = services.union(url)
        if name :
            services = services.union(__expand_eservice_names__(name))
        state.set(['Service', 'EnclaveServiceGroups', group, 'urls'], list(services))
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
        eservice_group.add_argument('--url', help='URL for enclave service', type=str)
        eservice_group.add_argument('--name', help='EService DB name for enclave services', type=str)
        eservice_group.add_argument('--random', help='No preferred enclave service', action='store_true')

    @classmethod
    def invoke(cls, state, bindings, group, url=None, name=None, random=None, **kwargs) :
        if random :
            state.set(['Service', 'EnclaveServiceGroups', group, 'preferred'], 'random')
            return True

        service_url = None
        if url :
            service_url = url
        elif name :
            service_info = __get_by_name__(name)
            if service_info is None :
                raise Exception('unknown eservice name; %s', name)
            service_url = service_info.service_url

        services = state.get(['Service', 'EnclaveServiceGroups', group, 'urls'], [])
        if service_url in services :
            state.set(['Service', 'EnclaveServiceGroups', group, 'preferred'], service_url)
        else :
            raise Exception('preferred URL not in the service group')
        return True

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_list(pscript.script_command_base) :
    name = "list"
    help = ""

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--group', help='Name of the eservice group', type=str, default="default")

    @classmethod
    def invoke(cls, state, bindings, group, **kwargs) :
        preferred = state.get(['Service', 'EnclaveServiceGroups', group, 'preferred'], 'random')
        services = state.get(['Service', 'EnclaveServiceGroups', group, 'urls'], [])
        cls.display_highlight("preferred: {0}".format(preferred))
        for service in services :
            cls.display(service)
        return list(services)

## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__subcommands__ = [
    script_command_add,
    script_command_remove,
    script_command_set,
    script_command_use,
    script_command_list,
]
do_eservice = pscript.create_shell_command('eservice', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'eservice', do_eservice)
