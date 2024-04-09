#!/usr/bin/env python

# Copyright 2019 Intel Corporation
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

import os
import sys
import argparse
import json
from pathlib import Path

import pdo.common.config as pconfig
import pdo.common.logger as plogger

import pdo.eservice.pdo_helper as pdo_enclave_helper
import pdo.eservice.pdo_enclave as pdo_enclave

import logging
logger = logging.getLogger(__name__)

import time



# -----------------------------------------------------------------
# -----------------------------------------------------------------
def GetBasename(save_path, config) :
    attempts = 0
    while True :
        try :
            logger.debug('initialize the enclave')
            enclave_config = config.get('EnclaveModule')
            spid = Path(os.path.join(enclave_config['sgx_key_root'], "sgx_spid.txt")).read_text().strip()
            info = pdo_enclave_helper.get_enclave_service_info(spid)

            logger.info('save MR_ENCLAVE and MR_BASENAME to %s', save_path)
            with open(save_path, "w") as file :
                file.write("MRENCLAVE:{0}\n".format(info[0]))
                file.write("BASENAME:{0}\n".format(info[1]))

            return

        except SystemError as se:
            # SGX_ERROR_BUSY error is not necessarily fatal, the SGX documentation
            # suggests restarting the request after a delay
            if str(se).find("SGX_ERROR_BUSY") < 0 :
                logger.critical('system error in enclave; %s', se)
                sys.exit(-1)

        except Exception as e :
            logger.critical('failed to initialize enclave; %s', e)
            sys.exit(-1)

        attempts = attempts + 1
        if 10 < attempts :
            logger.critical('wait for enclave failed')
            sys.exit(-1)

        logger.info('SGX_BUSY, attempt %s', attempts)
        time.sleep(10)

def GetIasCertificates(config) :
    # load, initialize and create signup info the enclave library
    # (signup info are not relevant here)
    # the creation of signup info includes getting a verification report from IAS
    try :
        enclave_config = config.get('EnclaveModule')
        pdo_enclave.initialize_with_configuration(enclave_config)
    except Exception as e :
        logger.error("unable to initialize a new enclave; %s", str(e))
        sys.exit(-1)

    try :
        nonce = '{0:016X}'.format(123456789)
        enclave_data = pdo_enclave.create_signup_info(nonce, nonce)

        # extract the IAS certificates from proof_data
        pd_dict =  json.loads(enclave_data.proof_data)
        ias_certificates = pd_dict['certificates']

        # dump the IAS certificates in the respective files
        with open(os.path.join(enclave_config['sgx_key_root'], "ias_root_ca.cert"), "w+") as file :
            file.write("{0}".format(ias_certificates[1]))

        with open(os.path.join(enclave_config['sgx_key_root'], "ias_signing.cert"), "w+") as file :
            file.write("{0}".format(ias_certificates[0]))

    except Exception as e :
        logger.error("unable to retrieve IAS certficates; %s", str(e))
        sys.exit(-1)

    finally :
        # do a clean shutdown of enclave
        pdo_enclave.shutdown()

def LocalMain(config, save_path) :
    GetBasename(save_path, config)
    GetIasCertificates(config)

    sys.exit(0)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def Main() :
    config_map = pconfig.build_configuration_map()

    # parse out the configuration file first
    conffiles = [ 'eservice.toml' ]
    confpaths = [ ".", "./etc", config_map['etc'] ]

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='directory to search for configuration files', nargs = '+')

    parser.add_argument('--identity', help='Identity to use for the process', required = True, type = str)
    parser.add_argument('--sgx-key-root', help='Path to SGX key root folder', type = str)
    parser.add_argument('--save', help='Where to save MR_ENCLAVE and BASENAME', type=str)

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    options = parser.parse_args()

    # first process the options necessary to load the default configuration
    if options.config :
        conffiles = options.config
    if options.config_dir :
        confpaths = options.config_dir

    # Location to save MR_ENCLAVE and MR_BASENAME
    if options.save :
        save_path = options.save

    config_map['identity'] = options.identity
    try :
        config = pconfig.parse_configuration_files(conffiles, confpaths, config_map)
    except pconfig.ConfigurationException as e :
        logger.error(str(e))
        sys.exit(-1)

    # set up the logging configuration
    if config.get('Logging') is None :
        config['Logging'] = {
            'LogFile' : '__screen__',
            'LogLevel' : 'INFO'
        }
    if options.logfile :
        config['Logging']['LogFile'] = options.logfile
    if options.loglevel :
        config['Logging']['LogLevel'] = options.loglevel.upper()
    plogger.setup_loggers(config.get('Logging', {}))
    sys.stdout = plogger.stream_to_logger(logging.getLogger('STDOUT'), logging.DEBUG)
    sys.stderr = plogger.stream_to_logger(logging.getLogger('STDERR'), logging.WARN)

    # set up the default enclave module configuration (if necessary)
    if config.get('EnclaveModule') is None :
        config['EnclaveModule'] = {
            'NumberOfEnclaves' : 7,
            'ias_url' : 'https://api.trustedservices.intel.com/sgx/dev',
            'sgx_key_root' : os.environ.get('PDO_SGX_KEY_ROOT', '.')
        }

    # override the enclave module configuration (if options are specified)
    if options.sgx_key_root :
        config['EnclaveModule']['sgx_key_root'] = options.sgx_key_root

    # GO!
    LocalMain(config, save_path)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
