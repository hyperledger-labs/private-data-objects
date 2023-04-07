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

"""
config.py -- functions to load configuration files with support for
variable expansion.

NOTE: functions defined in this file are designed to be run
before logging is enabled.
"""

from functools import reduce
import mergedeep
import os
import socket
import sys
from urllib.parse import urlparse
import warnings

import re
import toml
from string import Template
from pdo.common.utility import find_file_in_path

__all__ = [
    "ConfigurationException",
    "parse_configuration_files",
    "parse_configuration_file",
    "build_configuration_map"
    ]

# -----------------------------------------------------------------
# -----------------------------------------------------------------
__shared_configuration__ = None

def initialize_shared_configuration(config) :
    global __shared_configuration__
    if __shared_configuration__ is not None :
        raise RuntimeError("duplicate initialization of shared configuration")

    __shared_configuration__ = config     # may need deep copy, leave it shallow for now
    return __shared_configuration__

def shared_configuration(keylist=[], default=None) :
    global __shared_configuration__
    if __shared_configuration__ is None :
        raise RuntimeError("shared configuration is not initialized")

    try :
        return reduce(dict.get, keylist, __shared_configuration__) or default
    except TypeError :
        return None

    return __shared_configuration__

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ConfigurationException(Exception) :
    """
    A class to capture configuration exceptions.
    """

    def __init__(self, filename, message) :
        super().__init__(self, "Error in configuration file {0}: {1}".format(filename, message))

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def parse_configuration_files(cfiles, search_path, variable_map = None) :
    """
    Locate and parse a collection of configuration files stored in a
    TOML format.

    :param list(str) cfiles: list of configuration files to load
    :param list(str) search_path: list of directores where the files may be located
    :param dict variable_map: a set of substitutions for variables in the files
    :return dict:an aggregated dictionary of configuration information
    """
    config = {}
    files_found = []

    try :
        for cfile in cfiles :
            files_found.append(find_file_in_path(cfile, search_path))
    except FileNotFoundError as e :
        raise ConfigurationException(e.filename, e.strerror)

    for filename in files_found :
        try :
            mergedeep.merge(config, parse_configuration_file(filename, variable_map))
        except IOError as detail :
            raise ConfigurationException(filename, "IO error; {0}".format(str(detail)))
        except ValueError as detail :
            raise ConfigurationException(filename, "Value error; {0}".format(str(detail)))
        except NameError as detail :
            raise ConfigurationException(filename, "Name error; {0}".format(str(detail)))
        except KeyError as detail :
            raise ConfigurationException(filename, "Key error; {0}".format(str(detail)))
        except :
            raise ConfigurationException(filename, "Unknown error")

    return config

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def expand_expressions(text, variable_map) :
    """expand expressions found in a string, an expression is given
    in a ${{expr}}. For example, ${{port+5}} will expand to 7005 if
    port is set to 7000 in the variable_map.

    :param string text: template text
    :param dict variable_map: dictionary of variable bindings
    "returns string: text with expressions evaluated.
    """
    for item in re.findall(r'\${{(.*)}}', text, re.MULTILINE) :
        exp = '${{%s}}' % item
        val = str(eval(item, variable_map))
        text = text.replace(exp, val)

    return text

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def parse_configuration_file(filename, variable_map) :
    """
    Parse a configuration file expanding variable references
    using the Python Template library (variables are $var format)

    :param string filename: name of the configuration file
    :param dict variable_map: dictionary of expansions to use
    :returns dict: dictionary of configuration information
    """

    cpattern = re.compile('##.*$')

    with open(filename) as fp :
        lines = fp.readlines()

    text = ""
    for line in lines :
        text += re.sub(cpattern, '', line) + ' '

    if variable_map :
        text = expand_expressions(text, variable_map)
        text = Template(text).safe_substitute(variable_map)

    return toml.loads(text)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def build_configuration_map() :
    try :
        ContractHome = os.environ["PDO_HOME"]
        LedgerURL = os.environ["PDO_LEDGER_URL"]
        LedgerType = os.environ["PDO_LEDGER_TYPE"]
    except KeyError as ke :
        raise Exception("incomplete configuration, missing definition of {0}".format(str(ke)))

    # extract the ledger host from the ledger URL
    (LedgerHostName, _) = urlparse(LedgerURL).netloc.split(':')
    try :
        LedgerHostAddress = socket.gethostbyname(LedgerHostName)
    except Exception as e :
        # during CI builds the name may be meaningless and unresolvable
        # so we'll just pick the default local address, this should be
        # removed in the future when the build/install/config sequence
        # is more appropriately implemented
        LedgerHostAddress = "127.0.0.1"

    # these are effectively required by common-config, but clients dont
    # need them and we should be able to set reasonable defaults
    SPID = os.environ.get("PDO_SPID", "DEADBEEF00000000DEADBEEF00000000")
    SPID_API_KEY = os.environ.get("PDO_SPID_API_KEY", "deadbeef00000000deadbeef00000000")
    SGX_MODE = os.environ.get("SGX_MODE", "SIM")

    ContractHost = os.environ.get("PDO_HOSTNAME", os.environ.get("HOSTNAME", "localhost"))
    ContractHostAddress = socket.gethostbyname(ContractHost)
    ContractEtc = os.path.join(ContractHome, "etc")
    ContractKeys = os.path.join(ContractHome, "keys")
    ContractLogs = os.path.join(ContractHome, "logs")
    ContractLogLevel = os.environ.get("PDO_LOG_LEVEL", "warn")
    ContractData = os.path.join(ContractHome, "data")
    Interpreter = os.environ.get("PDO_INTERPRETER", "wawaka")
    LedgerKeyRoot = os.environ.get("PDO_LEDGER_KEY_ROOT", os.path.join(ContractEtc, "keys", "ledger"))
    HttpsProxy = os.environ.get("https_proxy", "")
    EserviceKeyFormat = 'pem'

    config_map = {
        'data' : ContractData,
        'eservice_key_format': EserviceKeyFormat,
        'etc'  : ContractEtc,
        'home' : ContractHome,
        'host' : ContractHost,
        'host_address' : ContractHostAddress,
        'interpreter' : Interpreter,
        'keys' : ContractKeys,
        'logs' : ContractLogs,
        'log_level' : ContractLogLevel,
        'ledger' : LedgerURL,
        'ledger_host_address' : LedgerHostAddress,
        'ledger_host_name' : LedgerHostName,
        'ledger_type': LedgerType,
        'ledger_key_root' : LedgerKeyRoot,
        'proxy' : HttpsProxy,
        'sgx_mode' : SGX_MODE,
        'spid' : SPID,
        'spid_api_key' : SPID_API_KEY
    }

    return config_map
