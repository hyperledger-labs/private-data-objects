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

# -----------------------------------------------------------------
# The next two functions are used to simplify development of
# commands for pdo-shell that can double as commands for development
# of other clients. It moves the argument specification out of the
# actual command and canonicalizes invocation.
#
# parser = argparse.ArgumentParser(prog='my_command')
# command_my_command = command(parser)
#
# subparsers = parser.add_subparsers(dest="subcommand")
#
# def my_subcommand(args=[], parent=subparsers, parents=[]) :
#     return subcommand(parent, args, parents)
#
# @my_subcommand(argument('--type', help='Type of service', type=str, required=True))
# def cmd_add(state, bindings, options) :
# ...
#
# An outside command can create the options namespace object
# with the following code:
#
# from types import SimpleNamespace
# cmd_add(state, bindings, SimpleNamespace(**kwargs))
# -----------------------------------------------------------------

def argument(*name_or_flags, **kwargs):
    """Function to simplify specification of command arguments
    for the subcommand property"""
    return ([*name_or_flags], kwargs)

def subcommand(parent, args=[], parents=[]):
    """Decorator for command functions that allows specification
    of command line options; principly used for clients."""
    def decorator(func):
        name = func.__name__[len('cmd_'):] if func.__name__.startswith('cmd_') else func.__name__
        parser = parent.add_parser(name, description=func.__doc__, parents=parents)
        for arg in args:
            parser.add_argument(*arg[0], **arg[1])
        parser.set_defaults(func=func)
    return decorator

def generate_command(parser) :
    def process_command(state, bindings, pargs) :
        options = parser.parse_args(pargs)
        if options.subcommand is None:
            parser.print_help()
        else:
            options.func(state, bindings, options)
    return process_command
