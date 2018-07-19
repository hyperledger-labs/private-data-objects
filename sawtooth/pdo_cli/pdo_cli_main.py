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
import getpass
import logging
import os
import sys
import traceback
import pkg_resources

from colorlog import ColoredFormatter

from pdo_cli.pdo_cli_client import PdoCliClient
from pdo_cli.pdo_cli_client import PdoCliException
from sawtooth.helpers.pdo_connect import PdoAddressHelper


DISTRIBUTION_NAME = 'pdo-sawtooth'

DEFAULT_URL = 'http://127.0.0.1:8008'


def create_console_handler(verbose_level):
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)

    if verbose_level == 0 or verbose_level == 1:
        clog.setLevel(logging.WARN)
    elif verbose_level == 2:
        clog.setLevel(logging.INFO)
    else:
        clog.setLevel(logging.DEBUG)

    return clog


def setup_loggers(verbose_level):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))


def create_parent_parser(prog_name):
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)

    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth) version {}')
        .format(version),
        help='display version information')

    return parent_parser


def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        parents=[parent_parser],
        formatter_class=argparse.RawDescriptionHelpFormatter)

    subparsers = parser.add_subparsers(title='subcommands', dest='command')
    add_json_command_parser(subparsers, parent_parser)
    add_show_command_parser(subparsers, parent_parser)
    add_list_command_parser(subparsers, parent_parser)
    add_delete_command_parser(subparsers, parent_parser)
    add_generate_test_enclave_info_parser(subparsers, parent_parser)
    add_generate_signer_key_parser(subparsers, parent_parser)
    add_ping_command_parser(subparsers, parent_parser)
    add_set_setting_parser(subparsers, parent_parser)
    return parser


def add_set_setting_parser(subparsers, parent_parser):
    message = 'Delete a Sawtooth global states for a specified PDO namespace'

    parser = subparsers.add_parser(
        'set-setting',
        parents=[parent_parser],
        description=message,
        help='Set a Sawtooth global setting <key> <value>')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        default=10,
        help='set time, in seconds, to wait for transaction to commit')

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='enable more verbose output')

    parser.add_argument(
        'key',
        type=str,
        help='Setting key to set')

    parser.add_argument(
        'value',
        type=str,
        help='Setting value to set')


def do_set_setting_command(args):
    key, value, wait = args.key, args.value, args.wait

    client = PdoCliClient(
        url=DEFAULT_URL if args.url is None else args.url,
        verbose=args.verbose > 0,
        keyfile=_get_keyfile(args))

    response = client.execute_set_setting(key, value, wait)
    print(response)


def add_ping_command_parser(subparsers, parent_parser):
    message = 'Executes a default transaction as a Transaction Processor ping test'

    parser = subparsers.add_parser(
        'ping',
        parents=[parent_parser],
        description=message,
        help='Submits a default ping transaction to test Transaction Processor')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        default=180,
        help='set time, in seconds, to wait for transaction to commit')

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='enable more verbose output')


def do_ping_command(args):
    wait = args.wait

    client = PdoCliClient(
        url=DEFAULT_URL if args.url is None else args.url,
        verbose=args.verbose > 0)

    client.execute_ping(wait)


def add_generate_signer_key_parser(subparsers, parent_parser):
    message = 'Generate public and private transaction signing key'

    parser = subparsers.add_parser(
        'generate-signing-key',
        parents=[parent_parser],
        description=message,
        help='Generate public and private transaction signing key')

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='enable more verbose output')


def do_generate_signing_key_command(args):
    client = PdoCliClient(url=DEFAULT_URL, verbose=args.verbose > 0)

    response = client.generate_signing_key_request()
    print(response)


def add_generate_test_enclave_info_parser(subparsers, parent_parser):
    message = 'Generate a test enclave register transaction info'

    parser = subparsers.add_parser(
        'generate-test-enclave',
        parents=[parent_parser],
        description=message,
        help='Generate a test enclave register transaction info')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='enable more verbose output')


def do_generate_test_enclave_info_command(args):
    client = PdoCliClient(
        url=DEFAULT_URL if args.url is None else args.url,
        verbose=args.verbose > 0,
        keyfile=_get_keyfile(args))

    response = client.generate_test_enclave_info_request()
    print(response)


def add_delete_command_parser(subparsers, parent_parser):
    message = 'Delete a Sawtooth global states for a specified PDO namespace'

    parser = subparsers.add_parser(
        'delete',
        parents=[parent_parser],
        description=message,
        help='Delete a Sawtooth global states for a specified PDO <namespace>')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        default=10,
        help='set time, in seconds, to wait for transaction to commit')

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='enable more verbose output')

    parser.add_argument(
        'namespace',
        type=str,
        help='PDO namespace to list states for; one of enclave, contract, ccl-info, ccl-state, pdo-all')


def do_delete_command(args):
    namespace, wait = args.namespace, args.wait

    client = PdoCliClient(
        url=DEFAULT_URL if args.url is None else args.url,
        verbose=args.verbose > 0,
        keyfile=_get_keyfile(args))

    if namespace == 'pdo-all':
       for ns in ['enclave', 'contract', 'ccl-info', 'ccl-state']:
           response = client.execute_delete_request(ns, wait)
           print(response)
    else:
        response = client.execute_delete_request(namespace, wait)
        print(response)


def add_list_command_parser(subparsers, parent_parser):
    message = 'List a Sawtooth global states for a specified PDO namespace'

    parser = subparsers.add_parser(
        'list',
        parents=[parent_parser],
        description=message,
        help='List a Sawtooth global states for a specified PDO <namespace>')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        default=10,
        help='set time, in seconds, to wait for transaction to commit')

    parser.add_argument(
        '--page-size',
        nargs='?',
        const=sys.maxsize,
        type=int,
        default=10,
        help='number of entries to retrieve at once from the Sawtooth API, a.k.a. page size')

    parser.add_argument(
        '--max-entries',
        nargs='?',
        const=sys.maxsize,
        type=int,
        default=50,
        help='maximum number of entries to display')

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='enable more verbose output')

    parser.add_argument(
        '-d', '--details',
        action='store_true',
        default = False,
        help="displayed detailed info for each state entry")

    parser.add_argument(
        'namespace',
        type=str,
        help='PDO namespace to list states for; one of enclave, contract, ccl-info, ccl-state, settings')


def do_list_command(args):
    namespace, wait, details = args.namespace, args.wait, args.details
    page_size, max_entries = args.page_size, args.max_entries

    print("url:", args.url)

    client = PdoCliClient(
        url=DEFAULT_URL if args.url is None else args.url,
        verbose=args.verbose > 0,
        keyfile=_get_keyfile(args))

    response = client.execute_list_request(namespace, details, page_size, max_entries, wait)
    print(response)


def add_show_command_parser(subparsers, parent_parser):
    message = 'Shows a Sawtooth global state by its address or PDO id'

    parser = subparsers.add_parser(
        'show',
        parents=[parent_parser],
        description=message,
        help='Show a PDO state defined in <type> and in <value>')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        default=10,
        help='set time, in seconds, to wait for transaction to commit')

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='enable more verbose output')

    parser.add_argument(
        'type',
        type=str,
        help='type of PDO state to display, one of address, enclave, contract, ccl, ccl-history, ccl-state, setting')

    parser.add_argument(
        'value',
        type=str,
        help='depends on the type and it is, correspondingly, Sawtooth address, '\
        'enclave_id, contract_id, contract_id, contract_id, contract_id:sate_hash, or'\
        'full or abbreviated setting name. '\
        'Abbreviated setting name is one of basenames, measurements, report-public-key')


def do_show_command(args):
    type, value, wait = args.type, args.value, args.wait

    client = PdoCliClient(
        url=DEFAULT_URL if args.url is None else args.url,
        verbose=args.verbose > 0,
        keyfile=_get_keyfile(args))

    response = client.execute_show_request(type, value, wait)
    print(response)


def add_json_command_parser(subparsers, parent_parser):
    message = 'Executes a transaction defined in a json file.'

    parser = subparsers.add_parser(
        'json',
        parents=[parent_parser],
        description=message,
        help='Submits a transaction defined in <json-file>')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

    parser.add_argument(
        '--enclave-keyfile',
        type=str,
        default="",
        help="Used to sign CCL transactions if the json input doesn't include signature")

    parser.add_argument(
        '-e', '--enclave',
        action='store_true',
        default = False,
        help="enforces an enclave transaction, needed only if there is no 'af' field in the json input")

    parser.add_argument(
        '-c', '--contract',
        action='store_true',
        default = False,
        help="enforces a contract transaction, needed only if there is no 'af' field in the json input")

    parser.add_argument(
        '--ccl', '--CCL',
        action='store_true',
        default = False,
        help="enforces a CCL transaction, needed only if there is no 'af' field in the json input")

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        default=10,
        help='set time, in seconds, to wait for transaction to commit')

    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='enable more verbose output')

    parser.add_argument(
        'json_file',
        type=str,
        help='name of a json object to create the transaction from')


def do_json_command(args):
    json_file_name, wait = args.json_file, args.wait

    try:
        with open(json_file_name) as json_file:
            json_input = json_file.read().strip()
            json_file.close()
    except OSError as err:
        raise PdoCliException('Failed to read json inout file: {}'.format(str(err)))

    address_family = ""

    if args.enclave:
        address_family = PdoAddressHelper().get_enclave_registry_family_name()
    elif args.contract:
        address_family = PdoAddressHelper().get_contract_registry_family_name()
    elif args.ccl:
        address_family = PdoAddressHelper().get_ccl_family_name()

    print(address_family)

    enclave_private_key = ""
    if args.enclave_keyfile:
        try:
            with open(args.enclave_keyfile) as fd:
                enclave_private_key = fd.read().strip()
                fd.close()
        except OSError as err:
            raise PdoCliException(
                'Failed to read private key: {}'.format(str(err)))

    client = PdoCliClient(
        url=DEFAULT_URL if args.url is None else args.url,
        verbose=args.verbose > 0,
        keyfile=_get_keyfile(args),
        enclave_signing_private_key=enclave_private_key)

    client.execute_json_transaction(json_input, address_family, wait)


def _get_keyfile(args):
    try:
        if args.keyfile is not None:
            return args.keyfile
    except AttributeError:
        return None

    real_user = getpass.getuser()
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")

    return '{}/{}.priv'.format(key_dir, real_user)


def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    if args is None:
        args = sys.argv[1:]
    parser = create_parser(prog_name)
    args = parser.parse_args(args)

    try:
        if args.verbose is None:
            verbose_level = 0
        else:
            verbose_level = args.verbose
        setup_loggers(verbose_level=verbose_level)
    except:
        parser.print_help()
        sys.exit(1)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'json':
        do_json_command(args)
    elif args.command == 'show':
        do_show_command(args)
    elif args.command == 'list':
        do_list_command(args)
    elif args.command == 'delete':
        do_delete_command(args)
    elif args.command == "generate-test-enclave":
        do_generate_test_enclave_info_command(args)
    elif args.command == "generate-signing-key":
        do_generate_signing_key_command(args)
    elif args.command == "ping":
        do_ping_command(args)
    elif args.command == "set-setting":
        do_set_setting_command(args)
    else:
        raise PdoCliException("invalid command: {}".format(args.command))


def main_wrapper():
    # pylint: disable=bare-except
    try:
        main()
    except (PdoCliException) as err:
        print("Error: {}".format(err), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        raise e
    except:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
