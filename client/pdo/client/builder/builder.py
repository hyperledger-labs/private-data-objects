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

import colorama
import json

__all__ = [
    'builder_command_base',
    'invocation_parameter',
    'process_structured_invocation_result',
]

## -----------------------------------------------------------------
# There are a number of ways to create a structure that can be re-used
# for defining commands include SimpleNamespace and namedtuples. There
# are advantages to those approaches. Here we chose a simple class
# structure to make it easier to inherit methods like the display
# functions. A different base builder_command_base could change the
# display functions for all commands that are derived from it.
## -----------------------------------------------------------------
class builder_command_base(object) :
    verbose = True
    name = "__undefined__"
    help = ""

    @classmethod
    def add_arguments(cls, parser) :
        pass


    @classmethod
    def display_warning(cls, *args) :
        print(colorama.Style.BRIGHT, colorama.Fore.YELLOW, *args, colorama.Style.RESET_ALL)

    @classmethod
    def display_error(cls, *args) :
        print(colorama.Style.BRIGHT, colorama.Fore.RED, *args, colorama.Style.RESET_ALL)

    @classmethod
    def display_highlight(cls, *args) :
        if cls.verbose :
            print(colorama.Style.BRIGHT, colorama.Fore.CYAN, *args, colorama.Style.RESET_ALL)

    @classmethod
    def display(cls, *args) :
        if cls.verbose :
            print(*args)

# -----------------------------------------------------------------
def invocation_parameter(s) :
    """argparse parameter conversion function for invocation request
    parameters, basically these parameters are JSON expressions
    """
    try :
        expr = json.loads(s)
        return expr
    except :
        return str(s)

## -----------------------------------------------------------------
def process_structured_invocation_result(result, path=[]) :
    """process the response from the ledger and convert it into
    a format that can be used later; specifically dictionaries
    are converted into a JSON string that can be read by an
    invocation parameter
    """
    if not result :
        return result

    if type(result) != dict :
        raise Exception("unexpected type of return value; {}".format(result))

    for p in path :
        result = result[p]

    return json.dumps(result)
