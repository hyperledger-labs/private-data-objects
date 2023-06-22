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
import logging

import pdo.client.builder as pbuilder

logger = logging.getLogger(__name__)

__all__ = [
    'script_command_base',
    'create_shell_command',
    ]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_base(pbuilder.builder_command_base) :
    @classmethod
    def invoke(cls, state, **kwargs) :
        raise NotImplementedError("must override invoke")

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def create_shell_command(command_name, subcommands) :
    """Map a set of script operations as subcommands for an aggregate
    command. This is generally used to expose a family of script commands
    as a single command for one of the shells.
    """

    def shell_command(state, bindings, pargs) :
        # set up parameters that are common to all operations
        parent_parser = argparse.ArgumentParser(add_help=False)
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

            symbol = options.symbol
            command = options.command

            # invoke the command
            kwargs = vars(options)
            kwargs['identity'] = identity
            kwargs['key_file'] = key_file

            del kwargs['symbol'], kwargs['command']

            result = command_map[command](state, bindings, **kwargs)

            # save the result that comes back
            if symbol :
                bindings.bind(symbol, result)

        finally :
            state.pop_identity()

        return True


    return shell_command
