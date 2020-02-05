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
import logging

logger = logging.getLogger(__name__)

import pdo.service_client.service_data.eservice as eservice_db

__all__ = ['command_eservice_db']

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def command_eservice_db(state, bindings, pargs) :
    """controller command to manage the enclave service database
    """

    parser = argparse.ArgumentParser(prog='eservice')

    subparsers = parser.add_subparsers(dest='command')

    add_parser = subparsers.add_parser('add', description='add an eservice to the database')
    add_parser.add_argument('--url', help='URL for the enclave service to add', type=str, required=True)
    add_parser.add_argument('--name', help='Short name for the enclave service', type=str, required=True)

    clear_parser = subparsers.add_parser('clear', description='remove all eservices in the database')
    list_parser = subparsers.add_parser('list', description='list eservices in the database')

    load_parser = subparsers.add_parser('load', description='load an eservice database')
    load_parser.add_argument('--database', help='Name of the eservice database to use', type=str, required=True)
    merge_group = load_parser.add_mutually_exclusive_group(required=False)
    merge_group.add_argument('--merge', help='Merge new database with current db', dest='merge', action='store_true')
    merge_group.add_argument('--no-merge', help='Overwrite current db with new database', dest='merge', action='store_false')
    load_parser.set_defaults(merge=False)

    remove_parser = subparsers.add_parser('remove', description='remove eservice from the database')
    remove_group = remove_parser.add_mutually_exclusive_group(required=True)
    remove_group.add_argument('--name', help='Short name for enclave service to remove', type=str)

    save_parser = subparsers.add_parser('save', description='save the current eservice database')
    save_parser.add_argument('--database', help='Name of the eservice database to use', type=str, required=True)

    options = parser.parse_args(pargs)

    default_database = state.get(['Service', 'EnclaveServiceDatabaseFile'])
    ledger_config = state.get(['Ledger'])

    if options.command == 'add' :
        if not eservice_db.add_by_url(ledger_config, options.url, name=options.name, update=True) :
            raise Exception('failed to add eservice {0} to the database'.format(options.name))
        return

    if options.command == 'clear' :
        eservice_db.clear_all_data()
        return

    if options.command == 'list' :
        enclave_names = list(eservice_db.get_enclave_names())
        enclave_names.sort()

        for enclave_name in enclave_names :
            enclave_info = eservice_db.get_by_name(enclave_name)
            enclave_short_id = _hashed_identity_(enclave_info.enclave_id)
            print("{0:<18} {1:<18} {2}".format(enclave_name, enclave_short_id, enclave_info.url))

    if options.command == 'load' :
        eservice_db.load_database(options.database, options.merge)
        return

    if options.command == 'remove' :
        eservice_db.remove_by_name(name=options.name)
        return

    if options.command == 'save' :
        eservice_db.save_database(options.database, True)
        return

    raise Exception('unknown subcommand')
