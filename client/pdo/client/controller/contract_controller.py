
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

import os, sys
import logging
import argparse

import copy
import cmd
import shlex
import time
import random
import re

from string import Template

logger = logging.getLogger(__name__)

__all__ = ['ContractController']

from pdo.client.controller.commands import *
from pdo.common.utility import find_file_in_path

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class State(object) :
    """
    """

    # --------------------------------------------------
    def __init__(self, config) :
        self.__data__ = copy.deepcopy(config)

    # --------------------------------------------------
    def set(self, keylist, value) :
        assert keylist

        current = self.__data__
        for key in keylist[:-1] :
            if key not in current :
                current[key] = {}
            current = current[key]

        current[keylist[-1]] = value

    # --------------------------------------------------
    def get(self, keylist, value=None) :
        assert keylist

        current = self.__data__
        for key in keylist :
            if key not in current :
                return value
            current = current[key]
        return current

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class Bindings(object) :
    """
    """

    # --------------------------------------------------
    def __init__(self, bindings = {}) :
        self.__bindings__ = copy.copy(bindings)

    # --------------------------------------------------
    def bind(self, variable, value) :
        self.__bindings__[variable] = value

    # --------------------------------------------------
    def isbound(self, variable) :
        return variable in self.__bindings__

    # --------------------------------------------------
    def expand(self, argstring) :
        try :
            template = Template(argstring)
            return template.substitute(self.__bindings__)

        except KeyError as ke :
            print('missing index variable {0}'.format(ke))
            return '-h'


# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# CLASS: ContractController
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class ContractController(cmd.Cmd) :
    """
    ContractController -- base class for building contract controllers

    Class defines the following variables:
    """

    # -----------------------------------------------------------------
    @staticmethod
    def ProcessScript(controller, filename, echo=False) :
        """
        ProcessScript -- process a file containing commands for the controller
        """
        saved = controller.echo
        try :
            controller.echo = echo
            cmdlines = ContractController.ParseScriptFile(filename)
            for cmdline in cmdlines :
                if controller.onecmd(cmdline) :
                    return False
        except Exception as e :
            controller.echo = saved
            raise e

        controller.echo = saved
        return True

    # -----------------------------------------------------------------
    @staticmethod
    def ParseScriptFile(filename) :
        cpattern = re.compile('##.*$')

        with open(filename) as fp :
            lines = fp.readlines()

            cmdlines = []
            for line in lines :
                line = re.sub(cpattern, '', line.strip())
                if len(line) > 0 :
                    cmdlines.append(line)

        return cmdlines

    # -----------------------------------------------------------------
    def __init__(self, config) :
        cmd.Cmd.__init__(self)

        self.echo = False
        self.bindings = Bindings(config.get('Bindings',{}))
        self.state = State(config)

        name = self.state.get(['Client', 'Identity'], "")
        self.prompt = "{0}> ".format(name)

    # -----------------------------------------------------------------
    def precmd(self, line) :
        if self.echo:
            print(line)

        return line

    # -----------------------------------------------------------------
    def postcmd(self, flag, line) :
        return flag

    # =================================================================
    # STOCK COMMANDS
    # =================================================================

    # -----------------------------------------------------------------
    def do_sleep(self, args) :
        """
        sleep <seconds> -- command to pause processing for a time (seconds).
        """

        pargs = shlex.split(self.bindings.expand(args))
        if len(pargs) == 0 :
            print('Time to sleep required: sleep <seconds>')
            return

        try :
            tm = int(pargs[0])
            print("Sleeping for {} seconds".format(tm))
            time.sleep(tm)
        except SystemExit as se :
            if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
            return

        except Exception as e :
            print('An error occurred processing {0}: {1}'.format(args, str(e)))
            return

    # -----------------------------------------------------------------
    def do_set(self, args) :
        """
        set -- assign a value to a symbol that can be retrieved with a $expansion
        """

        pargs = shlex.split(self.bindings.expand(args))

        try :
            parser = argparse.ArgumentParser(prog='set')
            parser.add_argument('-q', '--quiet', help='suppress printing the result', action='store_true')
            parser.add_argument('-s', '--symbol', help='symbol in which to store the identifier', required=True)
            parser.add_argument('-c', '--conditional', help='set the value only if it is undefined', action='store_true')

            eparser = parser.add_mutually_exclusive_group(required=True)
            eparser.add_argument('-i', '--identity', help='identity to use for retrieving public keys')
            eparser.add_argument('-f', '--file', help='name of the file to read for the value')
            eparser.add_argument('-v', '--value', help='string value to associate with the symbol')

            options = parser.parse_args(pargs)

            if options.conditional and self.bindings.isbound(options.symbol) :
                return

            value = options.value

            if options.identity :
                keypath = self.state.get(['Key', 'SearchPath'])
                keyfile = find_file_in_path("{0}_public.pem".format(options.identity), keypath)
                with open (keyfile, "r") as myfile:
                    value = myfile.read()

            if options.file :
                with open (options.file, "r") as myfile:
                    value = myfile.read()

            self.bindings.bind(options.symbol,value)
            if not options.quiet :
                print("${} = {}".format(options.symbol, value))
            return
        except SystemExit as se :
            if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
            return

        except Exception as e :
            print('An error occurred processing {0}: {1}'.format(args, str(e)))
            return

    # -----------------------------------------------------------------
    def do_echo(self, args) :
        """
        echo -- expand local $symbols
        """
        print(self.bindings.expand(args))

    # -----------------------------------------------------------------
    def do_identity(self, args) :
        """
        identity -- set the identity and keys to use for transactions
        """

        pargs = shlex.split(self.bindings.expand(args))

        try :
            parser = argparse.ArgumentParser(prog='identity')
            parser.add_argument('-n', '--name', help='identity to use for transactions', type=str, required=True)
            parser.add_argument('-f', '--key-file', help='file that contains the private key used for signing', type=str)
            options = parser.parse_args(pargs)

            self.prompt = "{0}> ".format(options.name)
            self.state.set(['Client', 'Identity'], options.name)
            self.state.set(['Key', 'FileName'], "{0}_private.pem".format(options.name))

            if options.key_file :
                self.state.set(['Key', 'FileName'], options.key_file)

            return
        except SystemExit as se :
            if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
            return

        except Exception as e :
            print('An error occurred processing {0}: {1}'.format(args, str(e)))
            return

    # -----------------------------------------------------------------
    def do_load_plugin(self, args) :
        """
        load -- load a new command processor from a file, the file should
        define a function called load_commands
        """

        pargs = shlex.split(self.bindings.expand(args))

        try :
            parser = argparse.ArgumentParser(prog='load_plugin')
            group = parser.add_mutually_exclusive_group(required=True)
            group.add_argument('-c', '--contract-class', help='load contract plugin from data directory', type=str)
            group.add_argument('-f', '--file', help='file from which to read the plugin', type=str)
            options = parser.parse_args(pargs)

            if options.file :
                plugin_file = options.file

            if options.contract_class :
                contract_paths = self.state.get(['Contract', 'SourceSearchPath'], ['.'])
                plugin_file = find_file_in_path(options.contract_class + '.py', contract_paths)

            with open(plugin_file) as f:
                code = compile(f.read(), plugin_file, 'exec')
                exec(code, globals())
            load_commands(ContractController)
            return
        except SystemExit as se :
            if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
            return

        except Exception as e :
            print('An error occurred processing {0}: {1}'.format(args, str(e)))
            return

    # -----------------------------------------------------------------
    def do_script(self, args) :
        """
        script -- load commands from a file
        """

        pargs = shlex.split(self.bindings.expand(args))

        try :
            parser = argparse.ArgumentParser(prog='script')
            parser.add_argument('-f', '--file', help='file from which to read commands', required=True)
            parser.add_argument('-e', '--echo', help='turn on command echoing', action='store_true')
            options = parser.parse_args(pargs)

            ContractController.ProcessScript(self, options.file, options.echo)
            return
        except SystemExit as se :
            if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
            return

        except Exception as e :
            print('An error occurred processing {0}: {1}'.format(args, str(e)))
            return

    # =================================================================
    # CONTRACT COMMANDS
    # =================================================================

    # -----------------------------------------------------------------
    def do_pservice(self, args) :
        """
        pservice -- manage provisioning service list
        """

        pargs = shlex.split(self.bindings.expand(args))

        try :
            pservice(self.state, self.bindings, pargs)

        except SystemExit as se :
            if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
            return

        except Exception as e :
            print('An error occurred processing {0}: {1}'.format(args, str(e)))
            return

    # -----------------------------------------------------------------
    def do_eservice(self, args) :
        """
        eservice -- manage enclave service list
        """

        pargs = shlex.split(self.bindings.expand(args))

        try :
            eservice(self.state, self.bindings, pargs)

        except SystemExit as se :
            if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
            return

        except Exception as e :
            print('An error occurred processing {0}: {1}'.format(args, str(e)))
            return

    # -----------------------------------------------------------------
    def do_contract(self, args) :
        """
        contract -- load contract for use
        """

        pargs = shlex.split(self.bindings.expand(args))

        try :
            contract(self.state, self.bindings, pargs)

        except SystemExit as se :
            if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
            return

        except Exception as e :
            print('An error occurred processing {0}: {1}'.format(args, str(e)))
            return

    # -----------------------------------------------------------------
    def do_create(self, args) :
        """
        create -- create a contract
        """

        pargs = shlex.split(self.bindings.expand(args))

        try :
            create(self.state, self.bindings, pargs)

        except SystemExit as se :
            if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
            return

        except Exception as e :
            print('An error occurred processing {0}: {1}'.format(args, str(e)))
            return

    # -----------------------------------------------------------------
    def do_send(self, args) :
        """
        send -- send a message to the contract
        """

        pargs = shlex.split(self.bindings.expand(args))

        try :
            send(self.state, self.bindings, pargs)

        except SystemExit as se :
            if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
            return

        except Exception as e :
            print('An error occurred processing {0}: {1}'.format(args, str(e)))
            return

    # -----------------------------------------------------------------
    def do_get_public_key(self, args) :
        """
        get_public_key -- get the public key from the current contract
        """

        pargs = shlex.split(self.bindings.expand(args))

        try :
            GetPublicKey.GetPublicKey(self, pargs)

        except SystemExit as se :
            if se.code > 0 : print('An error occurred processing {0}: {1}'.format(args, str(se)))
            return

        except Exception as e :
            print('An error occurred processing {0}: {1}'.format(args, str(e)))
            return


    # XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    # XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

    # -----------------------------------------------------------------
    def do_exit(self, args) :
        """
        exit -- shutdown the simulator and exit the command loop
        """
        return True

    # -----------------------------------------------------------------
    def do_EOF(self, args) :
        """
        exit -- shutdown the simulator and exit the command loop
        """
        return True
