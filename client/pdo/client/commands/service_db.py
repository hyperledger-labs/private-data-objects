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

import json

import pdo.client.builder.shell as pshell
import pdo.client.builder.script as pscript
import pdo.common.utility as putils
from pdo.service_client.service_data.service_data import ServiceDatabaseManager as service_data

import logging
logger = logging.getLogger(__name__)

__all__ = [
    'get_service_info',
    'add_service',
    'remove_service',
    'clear_service_data',
    'script_command_add',
    'script_command_remove',
    'script_command_rename',
    'script_command_verify',
    'script_command_clear',
    'script_command_list',
    'script_command_info',
    'script_command_import',
    'script_command_export',
    ]

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def add_select_parser(select_parser) :
    select_parser.add_argument(
        '--type',
        help='Type of service',
        type=str, choices=service_data.service_types,
        dest='service_type',
        required=True)

    select_group = select_parser.add_mutually_exclusive_group(required=True)
    select_group.add_argument('--name', help='Short name for service', type=str)
    select_group.add_argument('--url', help='URL for the service', type=str)
    select_group.add_argument('--verifying-key', help='Verifying key for the service', type=str)

## -----------------------------------------------------------------
## OPERATIONS
## -----------------------------------------------------------------

## -----------------------------------------------------------------
def get_service_info(state, service_type, service_url=None, service_name=None, service_identity=None) :
        if service_type not in service_data.service_types :
            raise RuntimeError("unknown service type; {}".format(service_type))

        if service_url :
            return service_data.local_service_manager.get_by_url(service_url, service_type)
        elif service_name :
            return service_data.local_service_manager.get_by_name(service_name, service_type)
        elif service_identity :
            return service_data.local_service_manager.get_by_identity(service_identity, service_type)
        else :
            raise RuntimeError("no service identifier provided")

## -----------------------------------------------------------------
def add_service(state, service_type, service_url, service_names=[]) :
    if service_type not in service_data.service_types :
        raise RuntimeError("unknown service type; {}".format(service_type))

    service_data.local_service_manager.store_by_url(
        service_url,
        service_type=service_type,
        service_names=service_names)

    return True

## -----------------------------------------------------------------
def remove_service(state, service_type, service_url=None, service_name=None, service_identity=None) :
    service_info = get_service_info(state, service_type, service_url, service_name, service_identity)
    service_data.local_service_manager.remove(service_info)
    return True

## -----------------------------------------------------------------
def clear_service_data(state) :
    service_data.local_service_manager.reset()
    return True

## -----------------------------------------------------------------
## COMMANDS
## -----------------------------------------------------------------

## -----------------------------------------------------------------
class script_command_add(pscript.script_command_base) :
    name = "add"
    help = "Add a new service to the service database"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--type',
            help='Type of service',
            type=str, choices=service_data.service_types,
            dest='service_type',
            required=True)

        subparser.add_argument('--url', help='URL for the service', type=str, required=True)
        subparser.add_argument('--name', help='Short name for service', type=str, nargs='*', default=[], dest='names')
        subparser.add_argument('--update', help='Update and verify enclave information', action="store_true"),

    @classmethod
    def invoke(cls, state, bindings, service_type, url, names, update=False, **kwargs) :
        if update :
            remove_service(state, service_type, service_url=url)

        return add_service(state, service_type, service_url=url, service_names=names)

## -----------------------------------------------------------------
class script_command_remove(pscript.script_command_base) :
    name = 'remove'
    help = 'Remove a service from the service database'
    @classmethod
    def add_arguments(cls, subparser) :
        add_select_parser(subparser)

    @classmethod
    def invoke(cls, state, bindings, service_type, url=None, name=None, verifying_key=None, **kwargs) :
        return remove_service(
            state,
            service_type,
            service_url=url,
            service_name=name,
            service_identity=verifying_key)

## -----------------------------------------------------------------
class script_command_rename(pscript.script_command_base) :
    name = "rename"
    help = "update the names associated with the service"

    @classmethod
    def add_arguments(cls, subparser) :
        add_select_parser(subparser)

        subparser.add_argument('--add', help='List of names to add for the service', type=str, nargs='+', default=[]),
        subparser.add_argument('--remove', help='List of names to remove for the service', type=str, nargs='+', default=[]),
        subparser.add_argument('--remove-all', help='Remove all names for the service', action="store_true"),

    @classmethod
    def invoke(cls, state, bindings, service_type, url=None, name=None, verifying_key=None, add=[], remove=[], remove_all=False) :
        old_service_info = get_service_info(
            state,
            service_type,
            service_url=url,
            service_name=name,
            service_identity=verifying_key)

        new_service_info = old_service_info.clone()

        remove_set = set(remove)
        if remove_all :
            remove_set = set(old_service_info.service_name)

        for n in remove_set :
            new_service_info.remove_name(n)

        add_set = set(add)
        for n in add_set :
            new_service_info.add_name(n)

        service_data.local_service_manager.update(old_service_info, new_service_info)
        return True

## -----------------------------------------------------------------
class script_command_verify(pscript.script_command_base) :
    name = "verify"
    help = "verify the integrity of the service information"

    @classmethod
    def add_arguments(cls, subparser) :
        add_select_parser(subparser)

    @classmethod
    def invoke(cls, state, bindings, service_type, url=None, name=None, verifying_key=None, **kwargs) :
        old_service_info = get_service_info(
            state,
            service_type,
            service_url=url,
            service_name=name,
            service_identity=verifying_key)

        new_service_info = old_service_info.clone()

        if not new_service_info.verify() :
            raise RuntimeError("failed to verify service {}".format(new_service_info.service_url))

        # save the updated information
        service_data.local_service_manager.update(old_service_info, new_service_info)
        return True

## -----------------------------------------------------------------
class script_command_clear(pscript.script_command_base) :
    name = "clear"
    help = "remove all information from the service database"

    @classmethod
    def invoke(cls, state, bindings, **kwargs) :
        clear_service_data(state)

## -----------------------------------------------------------------
class script_command_list(pscript.script_command_base) :
    name = "list"
    help = "list services in a specific service database"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--type',
            help='Type of service to add',
            type=str, choices=service_data.service_types,
            dest='service_type',
            required=True),
        subparser.add_argument(
            '--output',
            help='Python format string for output',
            type=str, default="{service_url}"),

    @classmethod
    def invoke(cls, state, bindings, service_type, output, **kwargs) :
        services = service_data.local_service_manager.list_services(service_type)
        for (service_url, service_info) in services :
            cls.display(output.format(**service_info.serialize()))

## -----------------------------------------------------------------
class script_command_info(pscript.script_command_base) :
    name = "info"
    help = "get information about a specific service"

    @classmethod
    def add_arguments(cls, subparser) :
        add_select_parser(subparser)

    @classmethod
    def invoke(cls, state, bindings, service_type, url=None, name=None, verifying_key=None, **kwargs) :
        service_info = get_service_info(
            state,
            service_type,
            service_url=url,
            service_name=name,
            service_identity=verifying_key)

        result = service_info.serialize()

        cls.display(result)
        return json.dumps(result)

## -----------------------------------------------------------------
class script_command_import(pscript.script_command_base) :
    name = "import"
    help = "import service information from a toml configuration file"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--file',
            help='Name of the toml file to import',
            dest='filename',
            type=str, required=True),

    @classmethod
    def invoke(cls, state, bindings, filename, **kwargs) :
        data_file = putils.find_file_in_path(filename, state.get(['Client', 'SearchPath'], ['.', './etc/']))
        service_data.local_service_manager.import_service_information(data_file)
        return True

## -----------------------------------------------------------------
class script_command_export(pscript.script_command_base) :
    name = "export"
    help = "export service information to a toml configuration file"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--file',
            help='Name of the toml file to import',
            dest='filename',
            type=str, required=True),

    @classmethod
    def invoke(cls, state, bindings, filename, **kwargs) :
        service_data.local_service_manager.export_service_information(filename)
        return True

## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__subcommands__ = [
    script_command_add,
    script_command_remove,
    script_command_rename,
    script_command_verify,
    script_command_clear,
    script_command_list,
    script_command_info,
    script_command_import,
    script_command_export,
]
do_service_db = pscript.create_shell_command('service_db', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'service_db', do_service_db)
