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
import importlib
import logging

import pdo.client.builder as pbuilder

logger = logging.getLogger(__name__)

__all__ = [
    'contract_op_base',
    'invoke_contract_op',
    'create_shell_command',
]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class contract_op_base(pbuilder.builder_command_base) :
    """Contract operation class provides a base class for defining
    operations on contract objects. Generally, there is one operation
    per method defined by the contract object.
    """
    @classmethod
    def invoke(cls, state, session, **kwargs) :
        raise NotImplementedError("must override invoke")

    @classmethod
    def log_invocation(cls, message, result) :
        logger.debug("invocation ({0}) --> ({1})".format(message, result))

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def invoke_contract_op(command, state, context, session, *args, **kwargs) :
    """invoke an operation on a specific contract using a particular identity

    the default identity comes from the context itself, but
    may be specified explicitly (as in, the operation may be
    performed on a contract object that is different from
    the creator of the contract object
    """
    identity = kwargs.get('identity') or context['identity']
    key_file = kwargs.get('key_file') or "{}_private.pem".format(identity)

    try :
        state.push_identity(identity, key_file)
        logger.debug('invoke op {} with identity {}'.format(command.__name__, identity))

        # pull the actual command from the module reference in the
        # context; this is a huge hack but gives a bit of the object
        # oriented-ness to the context storage without the need to
        # manage context entries as full-on objects
        module_name = context.get('module')
        if module_name :
            module = importlib.import_module(module_name)
            if hasattr(module, command.__name__) :
                command = getattr(module, command.__name__)

        result = command.invoke(state, session, *args, **kwargs)
    finally :
        state.pop_identity()

    return result

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def create_shell_command(command_name, subcommands) :
    """Map a set of script operations as subcommands for an aggregate
    command. This is generally used to expose a family of script commands
    as a single command for one of the shells.

    The main difference between the contract command and the script command
    is that the contract command adds a session parameter to deal with the
    connections to a specific contract.
    """

    def shell_command(state, bindings, pargs) :
        # set up parameters that are common to all operations
        parent_parser = argparse.ArgumentParser(add_help=False)
        parent_parser.add_argument('-e', '--enclave', help='URL of the enclave service', default="preferred", type=str)
        parent_parser.add_argument('-f', '--save_file', help='File where contract data is stored', type=str)
        parent_parser.add_argument('-w', '--wait', help='Wait for the transaction to commit', action='store_true')
        parent_parser.add_argument('-s', '--symbol', help='binding symbol for result', type=str)

        parent_parser.add_argument('--identity', help='Name of the user key file', type=str)
        parent_parser.add_argument('--key-file', help='Name of the user key file', type=str)

        parser = argparse.ArgumentParser(prog=command_name)
        subparsers = parser.add_subparsers(dest='command')

        command_map = {}
        for command in subcommands :
            subparser = subparsers.add_parser(command.name, help=command.help, parents=[parent_parser])
            command.add_arguments(subparser)
            command_map[command.name] = command.invoke

        # process the options
        options = parser.parse_args(pargs)
        if options.command is None or options.command == 'help' :
            parser.print_help()
            return True

        symbol = options.symbol
        command = options.command

        # if the key_file is set, then use it; otherwise, if the identity is set then
        # use the standard format for keys from identities
        if options.identity :
            identity = options.identity
            key_file = options.key_file or "{}_private.pem".format(identity)
        else :
            identity = state.identity
            key_file = options.key_file or state.private_key_file

        try :
            state.push_identity(identity, key_file)

            kwargs = vars(options)
            kwargs['identity'] = identity
            kwargs['key_file'] = key_file

            session_params = pbuilder.SessionParameters(**kwargs)
            del kwargs['wait'], kwargs['save_file'], kwargs['enclave'], kwargs['symbol'], kwargs['command']

            # invoke the command
            result = command_map[command](state, session_params, **kwargs)

            # save the result that comes back
            if symbol :
                bindings.bind(symbol, result)
        finally :
            state.pop_identity()


        return True

    return shell_command
