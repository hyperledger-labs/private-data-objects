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
import mergedeep
import toml

import pdo.client.builder.shell as pshell
import pdo.client.builder.script as pscript
import pdo.common.utility as putils
import pdo.common.config as pconfig

import logging
logger = logging.getLogger(__name__)

__all__ = [
    'script_command_load',
    'script_command_save',
    'script_command_list',
    'do_service_groups',
    'load_commands',
]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_load(pscript.script_command_base) :
    """Load the service group configuration from a file, the SearchPath configuration will
    be searched for the file
    """

    name = "load"
    help = "Load service group settings from a TOML file"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-f', '--file',
            help="Name of the file from where the groups will be loaded, destructive",
            dest='filename',
            required=True,
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
    def invoke(cls, state, bindings, filename, merge=True, **kwargs) :
        try :
            filename = putils.find_file_in_path(filename, state.get(['Client', 'SearchPath'], ['.', './etc']))
            info = pconfig.parse_configuration_file(filename, bindings)

            psgroups = info.get('ProvisioningServiceGroups', {})
            ssgroups = info.get('StorageServiceGroups', {})
            esgroups = info.get('EnclaveServiceGroups', {})

            if merge :
                psgroups = mergedeep.merge(state.get(['Service', 'ProvisioningServiceGroups'], {}), psgroups)
                ssgroups = mergedeep.merge(state.get(['Service', 'StorageServiceGroups'], {}), ssgroups)
                esgroups = mergedeep.merge(state.get(['Service', 'EnclaveServiceGroups'], {}), esgroups)

            state.set(['Service', 'ProvisioningServiceGroups'], psgroups)
            state.set(['Service', 'StorageServiceGroups'], ssgroups)
            state.set(['Service', 'EnclaveServiceGroups'], esgroups)

        except FileNotFoundError as e :
            cls.display_error('service group file does not exist; {}'.format(filename))
            return False

        except Exception as e :
            cls.display_error('failed to load service group file {}; {}'.format(filename, e))
            return False

        return True

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_save(pscript.script_command_base) :
    """Save the service configuration to a file, the filename is assumed to be absolute
    """

    name = "save"
    help = "Save service group settings to a TOML file"

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
        try :
            info = {}
            info['ProvisioningServiceGroups'] = state.get(['Service', 'ProvisioningServiceGroups'], {})
            info['StorageServiceGroups'] = state.get(['Service', 'StorageServiceGroups'], {})
            info['EnclaveServiceGroups'] = state.get(['Service', 'EnclaveServiceGroups'], {})
            with open(filename, "w") as outfile:
                toml.dump(info,outfile)
        except Exception as e :
            cls.display_error('failed to save service group configuration; {}'.format(e))
            return False

        return True

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_list(pscript.script_command_base) :
    name = "list"
    help = "List information about the service groups"

    @classmethod
    def invoke(cls, state, bindings, **kwargs) :
        services = state.get(['Service', 'EnclaveServiceGroups'], {})
        cls.display_highlight("Enclave Service Groups")
        for service in services.keys() :
            cls.display("\t{}".format(service))

        services = state.get(['Service', 'ProvisioningServiceGroups'], {})
        cls.display_highlight("Provisioning Service Groups")
        for service in services.keys() :
            cls.display("\t{}".format(service))

        services = state.get(['Service', 'StorageServiceGroups'], {})
        cls.display_highlight("Storage Service Groups")
        for service in services.keys() :
            cls.display("\t{}".format(service))

        return True

## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__subcommands__ = [
    script_command_load,
    script_command_save,
    script_command_list
]
do_service_groups = pscript.create_shell_command('service_groups', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'service_groups', do_service_groups)
