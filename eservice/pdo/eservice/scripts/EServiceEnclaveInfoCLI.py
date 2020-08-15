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

import pdo.common.config as pconfig
import pdo.common.logger as plogger

import pdo.eservice.pdo_helper as pdo_enclave_helper
import pdo.eservice.pdo_enclave as pdo_enclave

import logging
logger = logging.getLogger(__name__)

import time

# -----------------------------------------------------------------
# -----------------------------------------------------------------

def GetBasename(spid, save_path, config) :
    attempts = 0
    while True :
        try :
            logger.debug('initialize the enclave')
            enclave_config = {}
            enclave_config['EnclavePolicy'] = pdo_enclave_helper.parse_enclave_policy(config['EnclavePolicy'], config['Key']['SearchPath'])
            info = pdo_enclave_helper.get_enclave_service_info(spid, config=enclave_config)

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
        enclave_config = config['EnclaveModule']
        # add the enclave policy
        enclave_config['EnclavePolicy'] = pdo_enclave_helper.parse_enclave_policy(config['EnclavePolicy'], config['Key']['SearchPath'])
        pdo_enclave.initialize_with_configuration(enclave_config)
        nonce = '{0:016X}'.format(123456789)
        enclave_data = pdo_enclave.create_signup_info(nonce, nonce)
    except Exception as e :
        logger.error("unable to initialize a new enclave; %s", str(e))
        sys.exit(-1)

    # extract the IAS certificates from proof_data
    pd_dict =  json.loads(enclave_data.proof_data)
    ias_certificates = pd_dict['certificates']

    # dump the IAS certificates in the respective files
    with open(IasRootCACertificate_FilePath, "w+") as file :
        file.write("{0}".format(ias_certificates[1]))
    with open(IasAttestationVerificationCertificate_FilePathname, "w+") as file :
        file.write("{0}".format(ias_certificates[0]))

    # do a clean shutdown of enclave
    pdo_enclave.shutdown()
    return

def LocalMain(config, spid, save_path) :
    GetBasename(spid, save_path, config)
    GetIasCertificates(config)

    sys.exit(0)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

## -----------------------------------------------------------------
ContractHost = os.environ.get("HOSTNAME", "localhost")
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
ContractEtc = os.path.join(ContractHome, "etc")
ContractKeys = os.path.join(ContractHome, "keys")
ContractLogs = os.path.join(ContractHome, "logs")
ContractData = os.path.join(ContractHome, "data")
LedgerURL = os.environ.get("PDO_LEDGER_URL", "http://127.0.0.1:8008/")
ScriptBase = os.path.splitext(os.path.basename(sys.argv[0]))[0]

IasKeysPath = os.environ.get("PDO_SGX_KEY_ROOT")
IasRootCACertificate_FilePath = os.path.join(IasKeysPath, "ias_root_ca.cert")
IasAttestationVerificationCertificate_FilePathname = os.path.join(IasKeysPath, "ias_signing.cert")

config_map = {
    'base' : ScriptBase,
    'data' : ContractData,
    'etc'  : ContractEtc,
    'home' : ContractHome,
    'host' : ContractHost,
    'keys' : ContractKeys,
    'logs' : ContractLogs,
    'ledger' : LedgerURL
}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def Main() :
    # parse out the configuration file first
    conffiles = [ 'eservice.toml', 'enclave.toml' ]
    confpaths = [ ".", "./etc", ContractEtc ]

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='directory to search for configuration files', nargs = '+')

    parser.add_argument('--identity', help='Identity to use for the process', required = True, type = str)
    parser.add_argument('--spid', help='SPID to generate enclave basename', type=str)
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

    if options.spid :
        spid = options.spid

    global config_map
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

    # GO!
    LocalMain(config, spid, save_path)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
