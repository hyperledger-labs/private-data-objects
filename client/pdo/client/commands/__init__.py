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

__all__ = [
    'collection',
    'context',
    'contract',
    'eservice',
    'ledger',
    'pservice',
    'service_db',
    'service_groups',
    'sservice',
]

def load_common_commands(cmdclass) :
    """Load all of the command modules
    """
    import importlib
    def load_command(module_name) :
        command_module = importlib.import_module('pdo.client.commands.' + module_name)
        command_module.load_commands(cmdclass)

    for m in __all__ :
        load_command(m)
