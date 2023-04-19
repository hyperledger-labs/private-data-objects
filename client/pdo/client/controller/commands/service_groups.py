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
import os
import toml

import pdo.common.utility as putils

import logging
logger = logging.getLogger(__name__)

__all__ = [ 'command_service_groups', 'load_service_groups', 'save_service_groups' ]

#-----------------------------------------------------------------
def load_service_groups(state, groups_file, merge=True) :
    """load the service group configuration from a file, the SearchPath configuration will
    be searched for the file
    """
    groups_file = putils.find_file_in_path(groups_file, state.get(['Client', 'SearchPath'], ['.', './etc']))

    with open(groups_file, "r") as infile:
        info = toml.load(infile)

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

# -----------------------------------------------------------------
def save_service_groups(state, groups_file) :
    """save the service configuration to a file, the filename is assumed to be absolute
    """
    info = {}
    info['ProvisioningServiceGroups'] = state.get(['Service', 'ProvisioningServiceGroups'], {})
    info['StorageServiceGroups'] = state.get(['Service', 'StorageServiceGroups'], {})
    info['EnclaveServiceGroups'] = state.get(['Service', 'EnclaveServiceGroups'], {})
    with open(groups_file, "w") as outfile:
        toml.dump(info,outfile)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_service_groups(state, bindings, pargs) :
    """controller command to manage configuration files for service groups
    """
    subcommands = [ 'load', 'save', 'list' ]

    parser = argparse.ArgumentParser(prog='service_groups')
    subparsers = parser.add_subparsers(dest='command')

    subparser = subparsers.add_parser('load')
    subparser.add_argument(
        '--file',
        help="Name of the file from where the groups will be loaded, destructive",
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

    subparser = subparsers.add_parser('save')
    subparser.add_argument(
        '--file',
        help="Name of the file where the group configuration will be saveed",
        required=True,
        type=str)

    subparser = subparsers.add_parser('list')

    options = parser.parse_args(pargs)

    if options.command == 'load' :
        load_service_groups(state, options.file, options.merge)
        return

    if options.command == 'save' :
        save_service_groups(state, options.file)
        return

    if options.command == 'list' :
        services = state.get(['Service', 'EnclaveServiceGroups'], {})
        print("Enclave Service Groups")
        for service in services.keys() :
            print("\t{}".format(service))

        services = state.get(['Service', 'ProvisioningServiceGroups'], {})
        print("Provisioning Service Groups")
        for service in services.keys() :
            print("\t{}".format(service))

        services = state.get(['Service', 'StorageServiceGroups'], {})
        print("Storage Service Groups")
        for service in services.keys() :
            print("\t{}".format(service))
        return

    raise Exception('unknown subcommand')
