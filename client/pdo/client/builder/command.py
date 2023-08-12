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
import colorama
import logging
import functools
import glob
import importlib
import os
import re
import sys
import toml
import functools

logger = logging.getLogger(__name__)

import pdo.client.builder as pbuilder
import pdo.client.builder.contract as pcontract

__all__ = [
    'contract_command_base',
    'invoke_contract_cmd',
    'create_shell_command',
    ]


## -----------------------------------------------------------------
## -----------------------------------------------------------------
class contract_command_base(pbuilder.builder_command_base) :
    """Contract command class provides a base class for defining
    commands that span multiple contract objects. The unique aspect
    of contract commands is that there is a context that provides
    the bulk of the information about the contract and its relationship
    to other contracts.
    """
    @classmethod
    def invoke(cls, state, context, **kwargs) :
        raise NotImplementedError("must override invoke")

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def invoke_contract_cmd(command, state, context, *args, **kwargs) :
    """invoke a script in the context of an identity

    The default identity comes from the context itself, but
    may be specified explicitly (as in, the operation may be
    performed on a contract object that is different from
    the creator of the contract object

    @param identity: name of the entity to use for operations
    @param key_file : name of the file storing the keys to use for the transactions
    """
    identity = kwargs.get('identity') or context['identity']
    if identity is None :
        raise RuntimeError('missing identity for contract command operation')

    key_file = kwargs.get('key_file') or "{}_private.pem".format(identity)

    try :
        state.push_identity(identity, key_file)
        logger.debug('invoke cmd {} with identity {}'.format(command.__name__, identity))

        # pull the actual command from the module reference in the
        # context; this is a huge hack but gives a bit of the object
        # oriented-ness to the context storage without the need to
        # manage context entries as full-on objects
        module_name = context.get('module')
        if module_name :
            module = importlib.import_module(module_name)
            if hasattr(module, command.__name__) :
                command = getattr(module, command.__name__)

        result = command.invoke(state, context, *args, **kwargs)
    finally :
        state.pop_identity()

    return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def create_shell_command(command_name, subcommands) :
    """Create a contextualized contract command that can be called through
    the shell interface.
    """

    def shell_command(state, bindings, pargs) :
        # set up parameters that are common to all operations
        parent_parser = argparse.ArgumentParser(add_help=False)
        parent_parser.add_argument('--context-file', help="contract context file", default="./context.toml")
        parent_parser.add_argument('--contract', help="contract reference in the context file", required=True)
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

        contract = options.contract
        context_file = options.context_file

        pbuilder.Context.LoadContextFile(state, bindings, context_file)
        context = pbuilder.Context(state, contract)
        if not context.context :
            raise ValueError("unable to locate context {}".format(contract))

        # if the key_file is set, then use it; otherwise, if the identity is set then
        # use the standard format for keys from identities
        if options.identity :
            identity = options.identity
            key_file = options.key_file or "{}_private.pem".format(identity)
        elif context.get('identity') :
            identity = context.get('identity')
            key_file = options.key_file or "{}_private.pem".format(identity)
        else :
            identity = state.identity
            key_file = options.key_file or state.private_key_file

        try :
            state.push_identity(identity, key_file)

            kwargs = vars(options)
            kwargs['identity'] = identity
            kwargs['key_file'] = key_file

            del kwargs['context_file'], kwargs['contract'], kwargs['symbol'], kwargs['command']

            result = command_map[command](state, context, **kwargs)

            # save the result that comes back
            if symbol :
                bindings.bind(symbol, result)

        finally :
            state.pop_identity()

        pbuilder.Context.SaveContextFile(state, context_file)
        return True

    return shell_command
