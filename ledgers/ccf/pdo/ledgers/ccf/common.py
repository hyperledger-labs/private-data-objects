# Copyright 2024 Intel Corporation
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
import os
import sys
from urllib.parse import urlparse

from ccf.clients import Identity
from ccf.clients import CCFClient

from loguru import logger as LOG

# -----------------------------------------------------------------
# parse options and initialize the common variables
# -----------------------------------------------------------------
def parse_common_arguments(args, description, member_keys_required = False) :

    parser = argparse.ArgumentParser(description=description)

    parser.add_argument(
        '--logfile',
        help='Name of the log file, __screen__ for standard output',
        default='__screen__',
        type=str)

    parser.add_argument(
        '--loglevel',
        help='Logging level',
        default='WARNING',
        type=str)

    parser.add_argument(
        '--url',
        help='URL for the ledger',
        default = os.environ.get("PDO_LEDGER_URL"),
        type=str)

    parser.add_argument(
        '--interface',
        help='Host interface where CCF is listening',
        type=str)

    parser.add_argument(
        '--port',
        help='Port where CCF is listening',
        type=int,
        default=6600)

    parser.add_argument(
        '--key-dir',
        help='Directory where certificate files are located, defaults to PDO_LEDGER_KEY_ROOT',
        default=os.environ.get("PDO_LEDGER_KEY_ROOT"),
        type=str)

    parser.add_argument(
        '--cert',
        help='Name of the network certificate file',
        type=str,
        default='networkcert.pem')

    parser.add_argument(
        '--member',
        help="Name of the network membership certificate",
        default = "memberccf",
        type=str)

    (options, unprocessed_args) = parser.parse_known_args(args)

    # set up the logging
    LOG.remove()
    if options.logfile == '__screen__' :
        LOG.add(sys.stderr, level=options.loglevel)
    else :
        LOG.add(options.logfile)

    # precedence is given to ledger interface through the interface/port parameters; the fall back
    # is to use the ledger url parameter
    if options.interface :
        pass
    elif options.url :
        (options.interface, options.port) = urlparse(options.url).netloc.split(':')
    else :
        LOG.error('no ledger interface specified')
        sys.exit(-1)

    # the key directory must be specified either through the PDO_LEDGER_KEY_ROOT
    # environment variable or the key-dir parameter
    if not options.key_dir or not os.path.exists(options.key_dir) :
        LOG.error('unable to locate key dir')
        sys.exit(-1)

    network_cert = os.path.join(options.key_dir, options.cert)
    if not os.path.exists(network_cert) :
        LOG.error('network certificate ({}) does not exist'.format(network_cert))
        sys.exit(-1)

    # now create the client
    if member_keys_required :
        member_cert = os.path.join(options.key_dir, "{}_cert.pem".format(options.member))
        if not os.path.exists(member_cert) :
            LOG.error('member certificate ({}) does not exist'.format(member_cert))
            sys.exit(-1)

        member_key = os.path.join(options.key_dir, "{}_privk.pem".format(options.member))
        if not os.path.exists(member_key) :
            LOG.error('member key ({}) does not exist'.format(member_key))
            sys.exit(-1)

        try :
            client = CCFClient(
                options.interface,
                options.port,
                network_cert,
                session_auth=Identity(member_key, member_cert, "member"),
                signing_auth=Identity(member_key, member_cert, "member"),
            )
        except Exception as e:
            LOG.error('failed to connect to CCF service : {}'.format(str(e)))
            sys.exit(-1)

    else :
        try :
            client = CCFClient(
                options.interface,
                options.port,
                network_cert)
        except Exception as e:
            LOG.error('failed to connect to CCF service : {}'.format(str(e)))
            sys.exit(-1)

    # and return the client plus any operation-specific arguments that have not been processed
    return (options, unprocessed_args, client)
