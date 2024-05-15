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

# collections are a package for sharing multiple, interrelated
# contracts. more information is available in the file
# $PDO_SOURCE_ROOT/client/docs/collection.md

import argparse
import copy
import logging
import os
import toml
import typing

from zipfile import ZipFile

import pdo.client.builder.shell as pshell
import pdo.client.builder.script as pscript
import pdo.client.builder as pbuilder
from pdo.common.utility import experimental

logger = logging.getLogger(__name__)

__all__ = [
    'export',
    'import',
    'script_command_export',
    'script_command_import',
    'do_collection',
    'load_commands',
]

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def __find_contracts__(context : dict) -> typing.List[str] :
    """Find all contract save files in a context dictionary

    @type context : dict
    @param context : the export context
    """
    save_files = []
    for k, v in context.items() :
        if k == 'save_file' :
            save_files.append(v)
        elif isinstance(v, dict):
            save_files.extend(__find_contracts__(v))

    return save_files

# -----------------------------------------------------------------
# -----------------------------------------------------------------
@experimental
def export_contract_collection(
        context : pbuilder.context.Context,
        context_paths : typing.List[str],
        contract_cache : str,
        export_file : str) :
    """Export the context and associated contract files to a zip file that
    can be shared with others who want to use the contract

    @type context: pbuilder.context.Context
    @param context: current context
    @param context_paths : list of path expressions to retrieve values from a context
    @param contract_cache : name of the directory where contract save files are stored
    @param export_file : name of the file where the contract family will be written
    """

    # the context we create is initialized, mark it so
    export_context = {
        'contexts' : context_paths,
        'initialized' : True,
    }

    # copy the portions of the context specified in the context_paths

    # note: while there are fields in the context that are unnecessary for future use of the
    # contract, it is far easier to simply copy them here. at some point, this may be smarter about
    # only copying the fields that are necessary.

    for c in context_paths :
        # since the incoming contexts are paths, we need to make sure
        # we copy the context from/to the right location
        (*prefix, key) = c.split('.')
        ec = export_context
        for p in prefix :
            if p not in ec :
                ec[p] = {}
            ec = ec[p]
        ec[key] = copy.deepcopy(context.get_value(c))

    # now find all of the contract references in the exported context
    save_files = __find_contracts__(export_context)

    # and write the contract collection into the zip file
    with ZipFile(export_file, 'w') as zf :
        # add the context to the package, this has a canonical name
        zf.writestr('context.toml', toml.dumps(export_context))

        # add the contract save files to the package
        for s in save_files :
            contract_file_name = os.path.join(contract_cache, s)
            zf.write(contract_file_name, arcname=s)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
@experimental
def import_contract_collection(context_file_name : str, contract_cache : str, import_file : str) -> dict :
    """Import the context and contract files from a collections zip file

    @param context_file_name : name of the file to save imported context
    @param contract_cache : name of the directory where contract save files are stored
    @param import_file : name of the contract collection file to import
    @rtype: dict
    @return: the initialized context
    """
    with ZipFile(import_file, 'r') as zf :
        # extract the context file from the package and save it
        # in the specified file
        import_context = toml.loads(zf.read('context.toml').decode())
        with open(context_file_name, 'w') as cf :
            toml.dump(import_context, cf)

        # find all of the contract references in the exported context
        save_files = __find_contracts__(import_context)

        # extract the contract save files into the standard directory
        for save_file in save_files :
            zf.extract(save_file, contract_cache)

    return import_context

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_export(pscript.script_command_base) :
    name = "export"
    help = "Export a context and associated contract files to a contract collection file"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--collection-file', help="file where the collection will be saved", required=True, type=str)
        subparser.add_argument('--path', help="path to the context key", required=True, nargs='+', type=str)
        subparser.add_argument('--prefix', help="prefix for new contract context", type=str)

    @classmethod
    def invoke(cls, state, bindings, path, collection_file, prefix='', **kwargs) :
        data_directory = bindings.get('data', state.get(['Contract', 'DataDirectory']))
        contract_cache = bindings.get('save', os.path.join(data_directory, '__contract_cache__'))
        export_file = bindings.expand(collection_file)

        context = pbuilder.Context(state, prefix)
        export_contract_collection(context, path, contract_cache, export_file)

        return export_file

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class script_command_import(pscript.script_command_base) :
    name = "import"
    help = "Import a context and associated contract files from a contract collection file"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--collection-file', help="file where the collection will be saved", required=True, type=str)
        subparser.add_argument('--context-file', help="file where context will be saved", required=True, type=str)
        subparser.add_argument('--prefix', help="prefix for new contract context", type=str)

    @classmethod
    def invoke(cls, state, bindings, collection_file, context_file, prefix='', **kwargs) :
        data_directory = bindings.get('data', state.get(['Contract', 'DataDirectory']))
        contract_cache = bindings.get('save', os.path.join(data_directory, '__contract_cache__'))
        import_file = bindings.expand(collection_file)
        context_file = bindings.expand(context_file)

        if import_contract_collection(context_file, contract_cache, import_file) :
            prefix = prefix or []
            pbuilder.Context.LoadContextFile(state, bindings, context_file, prefix=prefix)
            return True

        return False

## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__subcommands__ = [
    script_command_export,
    script_command_import,
]
do_collection = pscript.create_shell_command('collection', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'collection', do_collection)
