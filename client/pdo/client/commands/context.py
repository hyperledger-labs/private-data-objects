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
import os

import pdo.client.builder.shell as pshell
import pdo.client.builder.script as pscript
import pdo.client.builder as pbuilder

logger = logging.getLogger(__name__)

__all__ = [
    'script_command_get',
    'script_command_set',
    'script_command_load',
    'script_command_save',
    'do_sservice',
    'load_commands',
]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_get(pscript.script_command_base) :
    name = "get"
    help = "Get the value of a context entry"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--context-file', help="file used to initialize context", type=str)
        subparser.add_argument('--path', help="path to the context key", required=True, type=str)
        subparser.add_argument('--prefix', help="prefix for new contract context", type=str)

    @classmethod
    def invoke(cls, state, bindings, path, context_file=None, prefix=None, **kwargs) :
        context_prefix = prefix or []

        if context_file :
            try :
                pbuilder.Context.LoadContextFile(state, bindings, *context_file, prefix=context_prefix)
            except ConfigurationException as ce :
                cls.display_error('failed to load context file; {}'.format(str(ce)))
                return False

        context = pbuilder.Context(state, context_prefix)
        return context.get(path)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_set(pscript.script_command_base) :
    name = "set"
    help = "Set the value of a context entry"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--context-file', help="file where context will be saved", type=str)
        subparser.add_argument('--path', help="path to the context key", required=True, type=str)
        subparser.add_argument('--prefix', help="prefix for new contract context", type=str)
        subparser.add_argument('-v', '--value', help="value to assign", required=True, type=pbuilder.invocation_parameter)

    @classmethod
    def invoke(cls, state, bindings, path, value, context_file=None, prefix=None, **kwargs) :
        context_prefix = prefix or []
        context = pbuilder.Context(state, context_prefix)
        context.set(path, value)

        if context_file :
            pbuilder.Context.SaveContextFile(state, context_file, prefix=context_prefix)

        return True

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_load(pscript.script_command_base) :
    name = "load"
    help = "Load context files"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--context-file', help="file where context will be saved", type=str)
        subparser.add_argument('--import-file', help="context file to import", nargs='+', required=True, type=str)
        subparser.add_argument('--prefix', help="prefix for new contract context", type=str)

    @classmethod
    def invoke(cls, state, bindings, import_file, context_file=None, prefix=None, **kwargs) :
        context_prefix = prefix or []

        # if the context file is specified and already exists, load it first
        if context_file and os.path.exists(context_file) :
            import_file = [context_file] + import_file

        try :
            pbuilder.Context.LoadContextFile(state, bindings, *import_file, prefix=context_prefix)
        except ConfigurationException as ce :
            cls.display_error('failed to load context file; {}'.format(str(ce)))
            return False

        # if the context file is specified, then save the results back to the file
        if context_file :
            pbuilder.Context.SaveContextFile(state, context_file, prefix=context_prefix)

        return True

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_save(pscript.script_command_base) :
    name = "save"
    help = "Save the current context to a file"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--context-file', help="file where context will be saved", type=str, required=True)
        subparser.add_argument('--prefix', help="prefix for new contract context", type=str)

    @classmethod
    def invoke(cls, state, bindings, context_file, prefix=None, **kwargs) :
        context_prefix = prefix or []
        pbuilder.Context.SaveContextFile(state, context_file, prefix=context_prefix)

        return True

## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__subcommands__ = [
    script_command_get,
    script_command_set,
    script_command_load,
    script_command_save,
]
do_context = pscript.create_shell_command('context', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'context', do_context)
