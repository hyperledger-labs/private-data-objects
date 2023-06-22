# Copyright 2022 Intel Corporation
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

from pdo.client.builder.shell import run_shell_command

import warnings
warnings.catch_warnings()
warnings.simplefilter("ignore")

# -----------------------------------------------------------------
def run_shell_context() :
    run_shell_command('do_context', 'pdo.client.commands.context')

# -----------------------------------------------------------------
def run_shell_contract() :
    run_shell_command('do_contract', 'pdo.client.commands.contract')

# -----------------------------------------------------------------
def run_shell_ledger() :
    run_shell_command('do_ledger', 'pdo.client.commands.ledger')

# -----------------------------------------------------------------
def run_shell_service_groups() :
    run_shell_command('do_service_groups', 'pdo.client.commands.service_groups')

# -----------------------------------------------------------------
def run_shell_eservice() :
    run_shell_command('do_eservice', 'pdo.client.commands.eservice')

# -----------------------------------------------------------------
def run_shell_sservice() :
    run_shell_command('do_sservice', 'pdo.client.commands.sservice')

# -----------------------------------------------------------------
def run_shell_pservice() :
    run_shell_command('do_pservice', 'pdo.client.commands.pservice')
