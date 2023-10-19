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
import importlib_resources
import logging
import os
import pathlib
import sys

import pdo.client.builder.shell as pshell

__all__ = [
    'install_plugin_resources',
]

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def _copy_to_destination_(source_path, destination_path) :
    """copy resources from the source path to the destination path. if the
    source path does not exist then return immediately. if the destination
    path does not exist then create it.
    """
    if not source_path.is_dir() :
        return

    dp = pathlib.Path(destination_path)
    dp.mkdir(parents=True, exist_ok=True)

    for f in source_path.iterdir() :
        logger.info('copy plugin resource {} to {}'.format(f.name, destination_path))
        dp.joinpath(f.name).write_bytes(f.read_bytes())
        dp.joinpath(f.name).chmod(f.stat().st_mode)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def install_plugin_resources() :
    """copy resources from plugin module into the pdo configuration directory tree.
    the assumption is that resources are stored in the plugin module in the following
    structure:
        module.resources.etc -- the family configuration file
        module.resources.contracts -- base64 encoded WASM contract source
        module.resources.scripts -- pdo-shell and bash scripts
        module.resources.context -- contract context template files
    this function is generally bound to an entry point to create a shell script
    that plugins can use to install resources

    the destination directories are taken from the bindings which are generally
    created through the standard configuration modules. destinations can be overridden
    with the '--bind' arguments.
    """

    (state, bindings, args) = pshell.parse_shell_command_line(sys.argv[1:])

    parser = argparse.ArgumentParser()
    parser.add_argument('--module', help='plugin module name where resources are stored', required=True, type=str)
    parser.add_argument('--family', help='name of the contract family to use for installation', required=True, type=str)

    options = parser.parse_args(args)
    module = options.module
    module_name = options.family

    resource_path = importlib_resources.files(module).joinpath('resources')

    # copy etc
    configuration_directory = os.path.join(bindings.expand('${etc}'), 'contracts')
    _copy_to_destination_(resource_path.joinpath('etc'), configuration_directory)

    # copy contracts
    contract_directory = os.path.join(bindings.expand('${home}'), 'contracts', module_name)
    _copy_to_destination_(resource_path.joinpath('contracts'), contract_directory)

    # copy scripts
    script_directory = os.path.join(bindings.expand('${home}'), 'contracts', module_name, 'scripts')
    _copy_to_destination_(resource_path.joinpath('scripts'), script_directory)

    # context
    context_template_directory = os.path.join(bindings.expand('${home}'), 'contracts', module_name, 'context')
    _copy_to_destination_(resource_path.joinpath('context'), context_template_directory)
