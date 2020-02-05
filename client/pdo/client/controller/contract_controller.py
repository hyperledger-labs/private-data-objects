
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
        saved = self.__bindings__.get(variable, '')
        self.__bindings__[variable] = value
        return saved

    # --------------------------------------------------
    def isbound(self, variable) :
        return variable in self.__bindings__

    # --------------------------------------------------
    def expand(self, argstring) :
        try :
            template = Template(argstring)
            return template.substitute(self.__bindings__)

        except KeyError as ke :
            raise Exception('missing index variable {0}'.format(ke))


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
        saved_echo = controller.echo
        saved_path = controller.bindings.bind('path', os.path.dirname(os.path.realpath(filename)))
        saved_script = controller.bindings.bind('script', os.path.basename(os.path.realpath(filename)))
        saved_non_interactive = controller.non_interactive
        try :
            controller.echo = echo
            controller.non_interactive = True
            cmdlines = ContractController.ParseScriptFile(filename)
            for cmdline in cmdlines :
                if controller.onecmd(cmdline) :
                    return False
        except Exception as e :
            controller.echo = saved_echo
            controller.bindings.bind('script', saved_script)
            controller.bindings.bind('path', saved_path)
            raise e

        controller.echo = saved_echo
        controller.bindings.bind('script', saved_script)
        controller.bindings.bind('path', saved_path)
        controller.non_interactive = saved_non_interactive

        return True

    # -----------------------------------------------------------------
    @staticmethod
    def ParseScriptFile(filename) :
        cpattern = re.compile('#[#!].*$')

        with open(filename) as fp :
            lines = fp.readlines()

        cmdlines = []
        for line in lines :
            line = re.sub(cpattern, '', line.strip())
            if len(line) > 0 :
                cmdlines.append(line)

        return cmdlines

    # -----------------------------------------------------------------
    def __init__(self, config, non_interactive=False) :
        cmd.Cmd.__init__(self)

        self.echo = False
        self.bindings = Bindings(config.get('Bindings',{}))
        self.state = State(config)
        self.exit_code = 0
        self.non_interactive = non_interactive

        self.deferred = 0
        self.deferred_lines = []
        self.nesting = []

        name = self.state.get(['Client', 'Identity'], "")
        self.prompt = "{0}> ".format(name)

        # save the identity so we can use it programmatically in scripts
        self.bindings.bind('identity', name)

    # -----------------------------------------------------------------
    def __arg_parse__(self, args) :
        """parse the command line in a consistent way, preserving the
        argument separate before binding expansion.
        """
        return map(lambda a : self.bindings.expand(a), shlex.split(args))

    # -----------------------------------------------------------------
    def __arg_error__(self, command, args, code) :
        """handle errors caused by argument processing
        """

        # code == 0 --> help was called
        if code == 0 :
            return False

        self.exit_code = code
        return self.non_interactive

    # -----------------------------------------------------------------
    def __error__(self, command, args, message) :
        """handle general errors caused by exceptions
        """
        print('"{0} {1}": {2}'.format(command, args, message))

        self.exit_code = 1
        return self.non_interactive

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
        if self.deferred > 0 : return False

        try :
            pargs = self.__arg_parse__(args)

            parser = argparse.ArgumentParser(prog='sleep')
            parser.add_argument('-q', '--quiet', help='suppress printing the result', action='store_true')
            parser.add_argument('-t', '--time', help='time to sleep', type=int, required=True)

            options = parser.parse_args(pargs)

            if not options.quiet :
                print("Sleeping for {} seconds".format(options.time))
            time.sleep(options.time)

        except SystemExit as se :
            return self.__arg_error__('sleep', args, se.code)
        except Exception as e :
            return self.__error__('sleep', args, str(e))

        return False


    # -----------------------------------------------------------------
    def do_set(self, args) :
        """set -- assign a value to a symbol that can be retrieved with a $expansion
        """
        if self.deferred > 0 : return False

        try :
            pargs = self.__arg_parse__(args)

            parser = argparse.ArgumentParser(prog='set')
            parser.add_argument('-q', '--quiet', help='suppress printing the result', action='store_true')
            parser.add_argument('-s', '--symbol', help='symbol in which to store the identifier', required=True)
            parser.add_argument('-c', '--conditional', help='set the value only if it is undefined', action='store_true')

            eparser = parser.add_mutually_exclusive_group(required=True)
            eparser.add_argument('-i', '--identity', help='identity to use for retrieving public keys')
            eparser.add_argument('-f', '--file', help='name of the file to read for the value')
            eparser.add_argument('-v', '--value', help='string value to associate with the symbol')
            eparser.add_argument('-r', '--random', help='generate a random string', type=int)

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

            if options.random :
                value = "{:X}".format(random.getrandbits(options.random))

            self.bindings.bind(options.symbol,value)
            if not options.quiet :
                print("${} = {}".format(options.symbol, value))

        except SystemExit as se :
            return self.__arg_error__('set', args, se.code)
        except Exception as e :
            return self.__error__('set', args, str(e))

        return False

    # -----------------------------------------------------------------
    def do_if(self, args) :
        """if -- start a conditional section of the script
        """
        self.nesting.append('if')
        if self.deferred > 0:
            self.deferred += 1
            return False

        try :
            pargs = self.__arg_parse__(args)

            parser = argparse.ArgumentParser(prog='if')
            parser.add_argument('--not', help='inverts the result of the query', dest='invert', action='store_true')

            eparser = parser.add_mutually_exclusive_group(required=True)
            eparser.add_argument('-z', '--zero', help="true if the argument is 0", type=int)
            eparser.add_argument('-n', '--null', help="true if the argument is empty string", type=str)
            eparser.add_argument('-e', '--equal', help="true if the arguments are equivalent", nargs=2)
            eparser.add_argument('-o', '--ordered', help="true if numbers are ordered", type=int, nargs='+')

            options = parser.parse_args(pargs)

            if options.zero is not None :
                condition = (options.zero == 0)
            elif options.null is not None :
                condition = (options.null == '')
            elif options.equal is not None :
                condition = (options.equal[0] == options.equal[1])
            elif options.ordered is not None :
                condition = True
                for i in range(1,len(options.ordered)) :
                    if options.ordered[i-1] >= options.ordered[i] :
                        condition = False
                        break
            else :
                condition = False

            if options.invert :
                condition = not condition

            if not condition :
                self.deferred += 1

        except SystemExit as se :
            return self.__arg_error__('if', args, se.code)
        except Exception as e :
            return self.__error__('if', args, str(e))

        return False

    # -----------------------------------------------------------------
    def do_else(self, args) :
        """else -- alternative section of the script
        """
        if len(self.nesting) == 0 or self.nesting[-1] != 'if' :
            return self.__error__('else', '', 'else without if')

        if self.deferred == 0 :
            self.deferred = 1
        elif self.deferred == 1 :
            self.deferred = 0

        return False

    # -----------------------------------------------------------------
    def do_fi(self, args) :
        """fi -- end a conditional section of the script
        """

        if len(self.nesting) == 0 or self.nesting[-1] != 'if' :
            return self.__error__('fi', '', 'fi without if')

        self.nesting.pop()

        if self.deferred > 0:
            self.deferred -= 1

        return False

    # -----------------------------------------------------------------
    def do_echo(self, args) :
        """echo -- expand local $symbols
        """
        if self.deferred > 0 : return False

        try :
            print(self.bindings.expand(args))
        except Exception as e :
            return self.__error__('echo', args, str(e))

        return False

    # -----------------------------------------------------------------
    def do_identity(self, args) :
        """identity -- set the identity and keys to use for transactions
        """
        if self.deferred > 0 : return False
        try :
            pargs = self.__arg_parse__(args)

            parser = argparse.ArgumentParser(prog='identity')
            parser.add_argument('-n', '--name', help='identity to use for transactions', type=str, required=True)
            parser.add_argument('-f', '--key-file', help='file that contains the private key used for signing', type=str)
            options = parser.parse_args(pargs)

            self.prompt = "{0}> ".format(options.name)
            self.state.set(['Client', 'Identity'], options.name)
            self.state.set(['Key', 'FileName'], "{0}_private.pem".format(options.name))

            # save the identity so we can use it programmatically in scripts
            self.bindings.bind('identity', options.name)

            if options.key_file :
                self.state.set(['Key', 'FileName'], options.key_file)

        except SystemExit as se :
            return self.__arg_error__('identity', args, se.code)
        except Exception as e :
            return self.__error__('identity', args, str(e))

        return False

    # -----------------------------------------------------------------
    def do_load_plugin(self, args) :
        """load -- load a new command processor from a file, the file should
        define a function called load_commands
        """
        if self.deferred > 0 : return False

        try :
            pargs = self.__arg_parse__(args)

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

        except SystemExit as se :
            return self.__arg_error__('load_plugin', args, se.code)
        except Exception as e :
            return self.__error__('load_plugin', args, str(e))

        return False

    # -----------------------------------------------------------------
    def do_script(self, args) :
        """script -- load commands from a file
        """
        if self.deferred > 0 : return False
        try :
            pargs = self.__arg_parse__(args)

            parser = argparse.ArgumentParser(prog='script')
            parser.add_argument('-f', '--file', help='file from which to read commands', required=True)
            parser.add_argument('-e', '--echo', help='turn on command echoing', action='store_true')
            options = parser.parse_args(pargs)

            ContractController.ProcessScript(self, options.file, options.echo)

        except SystemExit as se :
            return self.__arg_error__('script', args, se.code)
        except Exception as e :
            return self.__error__('script', args, str(e))

        return False

    # =================================================================
    # CONTRACT COMMANDS
    # =================================================================

    # -----------------------------------------------------------------
    def do_pservice(self, args) :
        """pservice -- manage provisioning service list
        """
        if self.deferred > 0 : return False

        try :
            pargs = self.__arg_parse__(args)
            pservice(self.state, self.bindings, pargs)

        except SystemExit as se :
            return self.__arg_error__('pservice', args, se.code)
        except Exception as e :
            return self.__error__('pservice', args, str(e))

        return False

    # -----------------------------------------------------------------
    def do_eservice(self, args) :
        """eservice -- manage enclave service lists for contract creation
        """
        if self.deferred > 0 : return False

        try :
            pargs = self.__arg_parse__(args)
            eservice(self.state, self.bindings, pargs)

        except SystemExit as se :
            return self.__arg_error__('eservice', args, se.code)
        except Exception as e :
            return self.__error__('eservice', args, str(e))

        return False

    # -----------------------------------------------------------------
    def do_eservice_db(self, args) :
        """eservice_db -- manage enclave service list
        """
        if self.deferred > 0 : return False

        try :
            pargs = self.__arg_parse__(args)
            eservice_db(self.state, self.bindings, pargs)

        except SystemExit as se :
            return self.__arg_error__('eservice_db', args, se.code)
        except Exception as e :
            return self.__error__('eservice_db', args, str(e))

        return False

    # -----------------------------------------------------------------
    def do_contract(self, args) :
        """contract -- load contract for use
        """
        if self.deferred > 0 : return False

        try :
            pargs = self.__arg_parse__(args)
            contract(self.state, self.bindings, pargs)

        except SystemExit as se :
            return self.__arg_error__('contract', args, se.code)
        except Exception as e :
            return self.__error__('contract', args, str(e))

        return False

    # -----------------------------------------------------------------
    def do_create(self, args) :
        """create -- create a contract
        """
        if self.deferred > 0 : return False

        try :
            pargs = self.__arg_parse__(args)
            create(self.state, self.bindings, pargs)

        except SystemExit as se :
            return self.__arg_error__('contract', args, se.code)
        except Exception as e :
            return self.__error__('contract', args, str(e))

        return False

    # -----------------------------------------------------------------
    def do_send(self, args) :
        """send -- send a message to the contract
        """
        if self.deferred > 0 : return False

        try :
            pargs = self.__arg_parse__(args)
            send(self.state, self.bindings, pargs)

        except SystemExit as se :
            return self.__arg_error__('send', args, se.code)
        except Exception as e :
            return self.__error__('send', args, str(e))

        return False

    # -----------------------------------------------------------------
    def do_get_public_key(self, args) :
        """get_public_key -- get the public key from the current contract
        """
        if self.deferred > 0 : return False

        try :
            pargs = self.__arg_parse__(args)
            GetPublicKey.GetPublicKey(self, pargs)

        except SystemExit as se :
            return self.__arg_error__('get_public_key', args, se.code)
        except Exception as e :
            return self.__error__('get_public_key', args, str(e))

        return False

    # XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    # XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

    # -----------------------------------------------------------------
    def do_exit(self, args) :
        """
        exit -- shutdown the simulator and exit the command loop
        """
        if self.deferred > 0 : return False

        try :
            pargs = self.__arg_parse__(args)
            parser = argparse.ArgumentParser(prog='exit')
            parser.add_argument('-v', '--value', help='exit code', type=int, default=0)
            options = parser.parse_args(pargs)

            self.exit_code = options.value

        except SystemExit as se :
            self.exit_code = 1
            return True

        except Exception as e :
            self.exit_code = 1
            return True

        return True

    # -----------------------------------------------------------------
    def do_EOF(self, args) :
        """
        exit -- shutdown the simulator and exit the command loop
        """
        self.exit_code = 0
        return True
