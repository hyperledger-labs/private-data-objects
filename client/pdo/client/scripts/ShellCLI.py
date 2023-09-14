#!/usr/bin/env python
# Copyright 2018 Intel Corporation
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

import logging
logger = logging.getLogger(__name__)

from pdo.client.controller.contract_controller import ContractController
import pdo.client.builder.shell as pshell

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def LocalMain(state, bindings, script_file=None) :
    # if there is a script file, process it; the interactive
    # shell will start unless there is an explicit exit in the script
    if script_file :
        shell = ContractController(state, bindings, echo=False, interactive=False)

        logger.debug("Processing script file %s", str(script_file))
        exit_code = ContractController.ProcessScript(shell, script_file)
        sys.exit(exit_code)

    shell = ContractController(state, bindings, echo=True, interactive=True)
    shell.cmdloop()
    print("")

    sys.exit(shell.exit_code)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def Main() :
    environment = pshell.parse_shell_command_line(sys.argv[1:])
    if environment is None :
        sys.exit(-1)

    (state, bindings, args) = environment

    script_file = None
    if args :
        script_file = args.pop(0)

        while args :
            try :
                key = args.pop(0).strip('-')
                val = args.pop(0)
            except ValueError :
                logger.error('unable to process script arguments')
                sys.exit(1)

            bindings.bind(key, val)

    # GO!
    LocalMain(state, bindings, script_file)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
