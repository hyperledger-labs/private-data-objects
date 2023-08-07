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
import functools
import glob
import importlib
import logging
import os
import sys
import types

import pdo.common.config as pconfig
import pdo.common.logger as plogger
import pdo.common.utility as putils
import pdo.service_client.service_data.eservice as eservice_db

from pdo.client.builder import State, Bindings, builder_command_base
import pdo.client.commands.service_groups as pgroups

logger = logging.getLogger(__name__)

__all__ = [
    'bind_shell_command',
    'initialize_environment',
    'parse_shell_command_line',
    'run_shell_command',
]

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def bind_shell_command(cmdclass, command_name, command) :
    """Create a command that can be evaluated by the pdo shell, typically
    this will be bound to an attribute in the pdo-shell command class through
    the load_plugin command.
    """
    def shell_command(cmdclass, args) :
        if cmdclass.deferred > 0 : return False

        try :
            pargs = cmdclass.__arg_parse__(args)
            command(cmdclass.state, cmdclass.bindings, pargs)
        except SystemExit as se :
            return cmdclass.__arg_error__(command_name, args, se.code)
        except Exception as e :
            return cmdclass.__error__(command_name, args, str(e))

        return False

    # there are some oddities about adding methods to an object
    # instance dynamically; this statement converts a "function"
    # into a method so it can be attached to an object
    # return types.MethodType(shell_command, cmdclass)
    setattr(cmdclass.__class__, 'do_' + command_name, shell_command)

# -----------------------------------------------------------------
def initialize_environment(options) :
    """Initialize a PDO client environment from a set of
    options specified in a simple namespace. Configuration includes
    loggers, site configuration, state, and bindings.
    """

    __config_map__ = pconfig.build_configuration_map()
    __config_map__['base'] = os.path.splitext(os.path.basename(sys.argv[0]))[0]
    __config_map__['save'] = os.path.join(__config_map__['data'], '__contract_cache__')
    __config_map__['identity'] = options.client_identity or '__unknown__'

    # set up the configuration mapping from the parameters
    if options.bind :
        for (k, v) in options.bind : __config_map__[k] = v

    __config_files__ = [
        os.path.join(__config_map__['etc'], 'pcontract.toml'),
        os.path.join(__config_map__['etc'], 'contracts', '*.toml'),
        os.path.join(os.environ.get("HOME"), 'etc', 'pcontract.toml'),
    ]

    # set up and parse the configuration files that will be loaded
    conffiles = __config_files__ + options.config
    conffiles = map(lambda f : os.path.realpath(f), functools.reduce(lambda x, f : x + glob.glob(f), conffiles, []))
    conffiles = list(conffiles)

    try :
        config = pconfig.parse_configuration_files(conffiles, [], __config_map__)
    except pconfig.ConfigurationException as e :
        logger.error(str(e))
        return None

    # set up the state based on the config
    state = State(config, identity=options.client_identity, private_key_file=options.client_key_file)

    # set up the initial variable bindings
    bindings = Bindings(__config_map__)

    # save the verbosity level to the command base
    builder_command_base.verbose = options.verbose

    # set up the logging configuration
    if options.logfile :
        state.set(['Logging', 'LogFile'], options.logfile)
    if options.loglevel :
        state.set(['Logging','LogLevel'], options.loglevel.upper())

    plogger.setup_loggers(state.get(['Logging']))

    # set up the ledger configuration
    if options.ledger :
        state.set(['Ledger', 'LedgerURL'], options.ledger)

    # set up the key search paths
    if options.key_dir :
        state.set(['Key', 'SearchPath'], options.key_dir)

    # set up the service configuration
    if options.service_db:
        state.set(['Service', 'EnclaveServiceDatabaseFile'], options.service_db)

    if options.service_groups :
        state.set(['Service', 'ServiceGroupFiles'], options.service_groups)

    # set up the data paths
    if options.data_dir :
        state.set(['Contract', 'DataDirectory'], options.data_dir)
    if options.source_dir :
        state.set(['Contract', 'SourceSearchPath'], options.source_dir)

    # make the configuration available to all of the PDO modules
    pconfig.initialize_shared_configuration(state.__data__)

    # load the service database files, it may not exist
    try :
        data_file = state.get(['Service', 'EnclaveServiceDatabaseFile'])
        data_file = putils.find_file_in_path(data_file, state.get(['Client', 'SearchPath'], ['.', './etc/']))
        eservice_db.load_database(data_file, True)
    except Exception as e :
        # log a warning but continue to run
        logger.warning('Failed to load eservice database; {}'.format(e))

    # load the service groups from the groups.toml file, nothing breaks if the
    # file doesn't load, but we do want to give an error message
    try :
        groupfiles = state.get(['Service', 'ServiceGroupFiles'], [])
        groupfiles = list(map(lambda f : os.path.realpath(bindings.expand(f)), groupfiles))
        for groupfile in groupfiles :
            if not pgroups.script_command_load.invoke(state, bindings, groupfile) :
                return None
    except Exception as e :
        # log a warning but continue to run
        logger.warning('Failed to load service group files; {}'.format(e))

    return (state, bindings)

# -----------------------------------------------------------------
def parse_shell_command_line(args) :
    """Parse command line parameters into the set of bindings
    that can be processed to initialize a PDO client
    """

    parser = argparse.ArgumentParser(allow_abbrev=False)

    # allow for override of bindings in the config map
    parser.add_argument('-m', '--mapvar', help='DEPRECATED!!! Use --bind', nargs=2, action='append', dest='bind')
    parser.add_argument('-b', '--bind', help='Define variables for configuration and script use', nargs=2, action='append')

    # add to the configuration files that will be loaded
    parser.add_argument('--config', help='full path name of additional configuration files', nargs = '+', default=[])

    # override specific values in the configuration files
    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    parser.add_argument('--ledger', help='URL for the ledger, override PDO_LEDGER_URL', type=str)
    parser.add_argument('--data-dir', help='Directory for storing generated files', type=str)
    parser.add_argument('--source-dir', help='Directories to search for contract source', nargs='+', type=str)
    parser.add_argument('--key-dir', help='Directories to search for key files', nargs='+')

    parser.add_argument('--service-db', help='full path to the service database file', type=str)
    parser.add_argument('--service-groups', help='full path name for service group specification', nargs='+', type=str)

    parser.add_argument('--client-identity', help='Name of the user key file', type=str)
    parser.add_argument('--client-key-file', help='Name of the user key file', type=str)

    # set common runtime variables
    parser.add_argument('--verbose', help='Show full exception', action='store_true')
    parser.add_argument('--abridged', help='Show limited information', dest='verbose', action='store_false')
    parser.set_defaults(verbose=True)

    (options, unprocessed_args) = parser.parse_known_args(args)

    # set up the configuration mapping from the parameters
    environment = initialize_environment(options)
    if environment is None :
        return None

    (state, bindings) = environment
    return (state, bindings, unprocessed_args)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def run_shell_command(command_name, module_name) :
    """Directly invoke a shell command from the command line,
    typically this will be used to create a bash shell executable
    for a particular command.
    """

    environment = parse_shell_command_line(sys.argv[1:])
    if environment is None :
        sys.exit(-1)

    (state, bindings, args) = environment

    try :
        module = importlib.import_module(module_name)

        command = getattr(module, command_name)
        if command is None :
            raise ValueError("unable to locate {} in module {}".format(command_name, module_name))

        command(state, bindings, args)
    except Exception as e :
        builder_command_base.display_error("Command failed: {}".format(str(e)))
        logger.exception(e)
        sys.exit(-1)
