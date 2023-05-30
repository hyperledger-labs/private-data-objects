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
import hashlib
import json

import logging
logger = logging.getLogger(__name__)

from pdo.common.utility import find_file_in_path
from pdo.client.utility import argument, subcommand, generate_command
from pdo.service_client.service_data.service_data import ServiceDatabaseManager as service_data

__all__ = [
    'command_service_db',
    'op_get_service_info',
    'op_add_service',
    'op_remove_service',
    'op_clear_service_data',
    ]

# -----------------------------------------------------------------
# -----------------------------------------------------------------
parser = argparse.ArgumentParser(
    prog="service_db",
    description="controller command to manage the enclave service database"
    )
command_service_db = generate_command(parser)

subparsers = parser.add_subparsers(dest="subcommand")

def service_db_subcommand(args=[], parent=subparsers, parents=[]) :
    return subcommand(parent, args, parents)

select_parser = argparse.ArgumentParser(add_help=False)
select_parser.add_argument('--type', help='Type of service', type=str, choices=service_data.service_types, required=True)
select_group = select_parser.add_mutually_exclusive_group(required=True)
select_group.add_argument('--name', help='Short name for service', type=str)
select_group.add_argument('--url', help='URL for the service', type=str)
select_group.add_argument('--identity', help='Verifying key for the service', type=str)

quiet_parser = argparse.ArgumentParser(add_help=False)
quiet_parser.add_argument('--quiet', help='Generate no output', action='store_true')

## -----------------------------------------------------------------
## OPERATIONS
## -----------------------------------------------------------------

## -----------------------------------------------------------------
def op_get_service_info(state, service_type, service_url=None, service_name=None, service_identity=None) :
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
def op_add_service(state, service_type, service_url, service_names=[]) :
    if service_type not in service_data.service_types :
        raise RuntimeError("unknown service type; {}".format(service_type))

    service_data.local_service_manager.store_by_url(
        service_url,
        service_type=service_type,
        service_names=service_names)

    return True

## -----------------------------------------------------------------
def op_remove_service(state, service_type, service_url=None, service_name=None, service_identity=None) :
    service_info = op_get_service_info(state, service_type, service_url, service_name, service_identity)
    service_data.local_service_manager.remove(service_info)
    return True

## -----------------------------------------------------------------
def op_clear_service_data(state) :
    service_data.local_service_manager.reset()
    return True

## -----------------------------------------------------------------
## COMMANDS
## -----------------------------------------------------------------

## -----------------------------------------------------------------
@service_db_subcommand([
    argument('--type', help='Type of service to add', type=str, choices=service_data.service_types, required=True),
    argument('--url', help='URL for the enclave service to add', type=str, required=True),
    argument('--name', help='Short name for the enclave service', type=str, nargs='*', default=[]),
    argument('--update', help='Update and verify enclave information', action="store_true"),
    ])

def cmd_add(state, bindings, options) :
    """add a new service to the service database"""

    if options.update :
        op_remove_service(
            state,
            options.type,
            service_url=options.url)

    op_add_service(
        state,
        options.type,
        options.url,
        service_names=options.name)

## -----------------------------------------------------------------
@service_db_subcommand([], parents=[select_parser])

def cmd_remove(state, bindings, options) :
    """remove a service from the service database"""
    op_remove_service(
        state,
        options.type,
        service_url=options.url,
        service_name=options.name,
        service_identity=options.identity)

## -----------------------------------------------------------------
@service_db_subcommand([
    argument('--add', help='List of names to add for the service', type=str, nargs='+', default=[]),
    argument('--remove', help='List of names to remove for the service', type=str, nargs='+', default=[]),
    argument('--remove-all', help='Remove all names for the service', action="store_true"),
    ],
     parents=[select_parser])

def cmd_rename(state, bindings, options) :
    """update the names associated with the service"""

    old_service_info = op_get_service_info(
        state,
        options.type,
        service_url=options.url,
        service_name=options.name,
        service_identity=options.identity)

    new_service_info = old_service_info.clone()

    remove_set = set(options.remove)
    if options.remove_all :
        remove_set = set(old_service_info.service_name)

    for n in remove_set :
        new_service_info.remove_name(n)

    add_set = set(options.add)
    for n in add_set :
        new_service_info.add_name(n)

    service_data.local_service_manager.update(old_service_info, new_service_info)

## -----------------------------------------------------------------
@service_db_subcommand([ ], parents=[select_parser])

def cmd_verify(state, bindings, options) :
    """verify the integrity of the service information"""

    old_service_info = op_get_service_info(
        state,
        options.type,
        service_url=options.url,
        service_name=options.name,
        service_identity=options.identity)

    new_service_info = old_service_info.clone()

    if not new_service_info.verify() :
        raise RuntimeError("failed to verify service {}".format(new_service_info.service_url))

    # save the updated information
    service_data.local_service_manager.update(old_service_info, new_service_info)

## -----------------------------------------------------------------
@service_db_subcommand()

def cmd_clear(state, bindings, options) :
    """remove all information from the service database"""
    op_clear_service_data(state)

## -----------------------------------------------------------------
@service_db_subcommand([
    argument('--type', help='Type of service to add', type=str, choices=service_data.service_types, required=True),
    argument('--output', help='Python format string for output', type=str, default="{service_url}"),
    ])

def cmd_list(state, bindings, options) :
    """list services in a specific service database"""
    services = service_data.local_service_manager.list_services(options.type)
    for (service_url, service_info) in services :
        print(options.output.format(**service_info.serialize()))

## -----------------------------------------------------------------
@service_db_subcommand([
    argument('-s', '--symbol', help='binding symbol for the result', type=str),
    ], parents=[select_parser, quiet_parser])

def cmd_info(state, bindings, options) :
    """get information about a specific service"""
    service_info = op_get_service_info(
        state,
        options.type,
        service_url=options.url,
        service_name=options.name,
        service_identity=options.identity)

    result = service_info.serialize()

    if not options.quiet :
        print(result)

    if options.symbol :
        bindings.bind(options.symbol, json.dumps(result))

## -----------------------------------------------------------------
@service_db_subcommand([
    argument('--file', help='Name of the toml file to import', type=str, required=True),
    ])
def cmd_import(state, bindings, options) :
    """import service information from a toml configuration file"""
    data_file = find_file_in_path(options.file, state.get(['Client', 'SearchPath'], ['.', './etc/']))
    service_data.local_service_manager.import_service_information(data_file)

## -----------------------------------------------------------------
@service_db_subcommand([
    argument('--file', help='Name of the toml file to write', type=str, required=True),
    ])
def cmd_export(state, bindings, options) :
    """export service information to a toml configuration file"""
    service_data.local_service_manager.export_service_information(options.file)


## -----------------------------------------------------------------
## -----------------------------------------------------------------
# def command_service_db(state, bindings, pargs) :
#     options = parser.parse_args(pargs)
#     if options.subcommand is None:
#         parser.print_help()
#     else:
#         options.func(state, bindings, options)
