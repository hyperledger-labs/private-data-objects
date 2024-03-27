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
import json
import mergedeep
import toml

import pdo.client.builder.shell as pshell
import pdo.client.builder.script as pscript
import pdo.common.utility as putils
import pdo.common.config as pconfig
import pdo.client.commands.service_db as pservice

from pdo.service_client.service_data.service_groups import GroupsDatabaseManager as group_data

import logging
logger = logging.getLogger(__name__)

__all__ = [
    'get_group_info',
    'add_group',
    'remove_group',
    'clear_service_data',
    'script_command_clear',
    'script_command_export',
    'script_command_import',
    'script_command_info',
    'script_command_list',
    'do_service_groups',
    'load_commands',
]

## -----------------------------------------------------------------
## OPERATIONS
## -----------------------------------------------------------------

## -----------------------------------------------------------------
def get_group_info(service_type, group_name) :
    if service_type not in group_data.service_types :
        raise RuntimeError("unknown service type; {}".format(service_type))

    return group_data.local_groups_manager.get_by_name(group_name, service_type)

## -----------------------------------------------------------------
def add_group(service_type : str, group_name : str, service_urls, **kwargs) :
    """Add a new service group or update an existing one
    """
    if service_type not in group_data.service_types :
        raise RuntimeError("unknown service type; {}".format(service_type))

    # make sure that all of the URLs are registered in the service_db
    for u in service_urls :
        _ = pservice.get_service_info(service_type, service_url=u)

    info = group_data.service_group_map[service_type](group_name, service_urls, **kwargs)
    group_data.local_groups_manager.update(info)

## -----------------------------------------------------------------
def remove_group(service_type : str, group_name : str) :
    """Remove a group from the groups database
    """
    if service_type not in group_data.service_types :
        raise RuntimeError("unknown service type; {}".format(service_type))

    # no problem if the group doesn't exist
    try :
        info = get_group_info(service_type, group_name)
        group_data.local_groups_manager.remove(info)
    except :
        pass

## -----------------------------------------------------------------
def clear_data() :
    """Remove all data from the groups database
    """
    group_data.local_groups_manager.reset()

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_import(pscript.script_command_base) :
    """Load the service group configuration from a file, the SearchPath configuration will
    be searched for the file
    """

    name = "import"
    help = "Import service group settings from a TOML file"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-f', '--file',
            help="Name of the file from where the groups will be loaded, destructive",
            dest='filenames',
            required=True,
            nargs='+',
            type=str)
        subparser.add_argument(
            '--merge',
            help="Merge new entries with existing entries",
            default=True,
            action='store_true')
        subparser.add_argument(
            '--no-merge',
            dest='merge',
            help="Clear the database before loading",
            action='store_false')

    @classmethod
    def invoke(cls, state, bindings, filenames, merge=True, **kwargs) :
        search_path = state.get(['Client', 'SearchPath'], ['.', './etc/'])
        groups_info = pconfig.parse_configuration_files(filenames, search_path, bindings)

        if not merge :
            clear_data()

        group_data.local_groups_manager.import_group_information(groups_info)
        return True

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_export(pscript.script_command_base) :
    """Save the service configuration to a file, the filename is assumed to be absolute
    """

    name = "export"
    help = "Export service group settings to a TOML file"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--file',
            help="Name of the file where the group configuration will be saveed",
            dest='filename',
            required=True,
            type=str)

    @classmethod
    def invoke(cls, state, bindings, filename, **kwargs) :
        groups_info = group_data.local_groups_manager.export_group_information()
        with open(filename, "w") as outfile:
            toml.dump(groups_info, outfile)

        return True

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_clear(pscript.script_command_base) :
    name = "clear"
    help = "remove all information from the groups database"

    @classmethod
    def invoke(cls, state, bindings, **kwargs) :
        clear_data()

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_info(pscript.script_command_base) :
    name = "info"
    help = "get information about a specific service group"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--type',
            help='Type of service to add',
            type=str, choices=group_data.service_types,
            dest='service_type',
            required=True),

        subparser.add_argument(
            '--group',
            help='Name of the service group',
            type=str,
            dest='group_name',
            required=True),

    @classmethod
    def invoke(cls, state, bindings, service_type, group_name, **kwargs) :
        group_info = get_group_info(service_type, group_name)
        result = group_info.serialize()

        cls.display(result)
        return json.dumps(result)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_list(pscript.script_command_base) :
    name = "list"
    help = "List information about the service groups"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '--type',
            help='Type of service to add',
            type=str, choices=group_data.service_types,
            dest='service_type',
            required=True),
        subparser.add_argument(
            '--output',
            help='Python format string for output',
            type=str, default="{name}: {urls}"),

    @classmethod
    def invoke(cls, state, bindings, service_type, output, **kwargs) :
        groups = group_data.local_groups_manager.list_groups(service_type)
        for (group_name, group_info) in groups :
            serialized = group_info.serialize()
            serialized['name'] = group_name
            cls.display(output.format(**serialized))

        return True

## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__subcommands__ = [
    script_command_clear,
    script_command_export,
    script_command_import,
    script_command_info,
    script_command_list,
]
do_service_groups = pscript.create_shell_command('service_groups', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'service_groups', do_service_groups)
