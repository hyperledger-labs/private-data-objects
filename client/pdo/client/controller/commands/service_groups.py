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
import toml

import logging
logger = logging.getLogger(__name__)

__all__ = [ 'command_service_groups', 'import_service_groups', 'export_service_groups' ]

#-----------------------------------------------------------------
def import_service_groups(state, groups_file) :
    with open(groups_file, "r") as infile:
        info = toml.load(infile)
    state.set(['Service', 'ProvisioningServiceGroups'], info.get('ProvisioningServiceGroups', {}))
    state.set(['Service', 'StorageServiceGroups'], info.get('StorageServiceGroups', {}))
    state.set(['Service', 'EnclaveServiceGroups'], info.get('EnclaveServiceGroups', {}))

# -----------------------------------------------------------------
def export_service_groups(state, groups_file) :
    info = {}
    info['ProvisioningServiceGroups'] = state.get(['Service', 'ProvisioningServiceGroups'], {})
    info['StorageServiceGroups'] = state.get(['Service', 'StorageServiceGroups'], {})
    info['EnclaveServiceGroups'] = state.get(['Service', 'EnclaveServiceGroups'], {})
    with open(options.file, "w") as outfile:
        toml.dump(info,outfile)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_service_groups(state, bindings, pargs) :
    """controller command to manage configuration files for service groups
    """
    subcommands = [ 'import', 'export', 'list' ]

    parser = argparse.ArgumentParser(prog='service_groups')
    subparsers = parser.add_subparsers(dest='command')

    subparser = subparsers.add_parser('import')
    subparser.add_argument(
        '--file',
        help="Name of the file from where the groups will be imported, destructive",
        required=True,
        type=str)

    subparser = subparsers.add_parser('export')
    subparser.add_argument(
        '--file',
        help="Name of the file where the group configuration will be exported",
        required=True,
        type=str)

    subparser = subparsers.add_parser('list')

    options = parser.parse_args(pargs)

    if options.command == 'import' :
        import_service_groups(state, options.file)
        return

    if options.command == 'export' :
        export_service_groups(state, options.file)
        return

    if options.command == 'list' :
        services = state.get(['Service', 'EnclaveServiceGroups'], [])
        print("Enclave Service Groups")
        for service in services.keys() :
            print("\t{}".format(service))

        services = state.get(['Service', 'ProvisioningServiceGroups'], [])
        print("Provisioning Service Groups")
        for service in services.keys() :
            print("\t{}".format(service))

        services = state.get(['Service', 'StorageServiceGroups'], [])
        print("Storage Service Groups")
        for service in services.keys() :
            print("\t{}".format(service))
        return

    raise Exception('unknown subcommand')
