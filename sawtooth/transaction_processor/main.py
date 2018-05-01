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

import sys
import argparse
import logging
import pkg_resources

from colorlog import ColoredFormatter

from sawtooth_sdk.processor.core import TransactionProcessor
from transaction_processor.enclave_registry_handler import ContractEnclaveRegistryTransactionHandler
from transaction_processor.contract_registry_handler import ContractRegistryTransactionHandler
from transaction_processor.ccl_registry_handler import ContractCclTransactionHandler

DISTRIBUTION_NAME = 'sawtooth-pdo-families'


LOGGER = logging.getLogger(__name__)

def create_console_handler(verbose_level):
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)

    if verbose_level == 0:
        clog.setLevel(logging.WARN)
    elif verbose_level == 1:
        clog.setLevel(logging.INFO)
    else:
        clog.setLevel(logging.DEBUG)

    return clog


def init_console_logging(verbose_level=2):
    logger = logging.getLogger()
    if verbose_level == 0:
        logger.setLevel(logging.WARN)
    elif verbose_level == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.DEBUG)

    if verbose_level > 0:
        logger.addHandler(create_console_handler(verbose_level))


def parse_args(args):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        '-C', '--connect',
        default='tcp://localhost:4004',
        help='Endpoint for the validator connection')

    parser.add_argument('-v', '--verbose',
                        action='count',
                        default=0,
                        help='Increase output sent to stderr')

    parser.add_argument(
        '-e', '--enclave',
        action='store_true',
        default = False,
        help="start enclave registry transaction family")

    parser.add_argument(
        '-c', '--contract',
        action='store_true',
        default = False,
        help="start contract registry transaction family")

    parser.add_argument(
        '--ccl', '--CCL',
        action='store_true',
        default = False,
        help="start CCL registry transaction family")

    parser.add_argument(
        '--debug-on',
        action='store_true',
        default = False,
        help="enable state deletion and signature verification by-pass for predefined tests")

    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' version {}').format(version),
        help='print version information')

    return parser.parse_args(args)


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    opts = parse_args(args)

    init_console_logging(verbose_level=opts.verbose)

    LOGGER.info("opts.verbose: %s", opts.verbose)
    LOGGER.info("opts.connect (url): %s", opts.connect)

    processor = TransactionProcessor(url=opts.connect)
    debug_on = opts.debug_on

    enclave_handler = ContractEnclaveRegistryTransactionHandler(debug_on)
    contract_handler = ContractRegistryTransactionHandler(debug_on)
    ccl_handler = ContractCclTransactionHandler(debug_on)

    start_enclave, start_contract, start_ccl = opts.enclave, opts.contract, opts.ccl

    if not start_enclave and not start_contract and not start_ccl:
        # none of the "-c, -e, -ccl' options is explicitly specified, enable all
        start_enclave = start_contract = start_ccl = True

    if start_enclave:
        LOGGER.warning("Starting PDO Contract Enclave Registry TP")
        processor.add_handler(enclave_handler)

    if start_contract:
        LOGGER.warning("Starting PDO Contract Registry TP")
        processor.add_handler(contract_handler)

    if start_ccl:
        LOGGER.warning("Starting PDO CCL Contract TP")
        processor.add_handler(ccl_handler)

    try:
        processor.start()
    except KeyboardInterrupt:
        pass
    finally:
        processor.stop()
