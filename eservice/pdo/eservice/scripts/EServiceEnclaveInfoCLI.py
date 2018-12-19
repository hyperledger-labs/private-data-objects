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

import os
import sys
import argparse

import pdo.common.logger as plogger

import pdo.eservice.pdo_helper as pdo_enclave_helper

import logging
logger = logging.getLogger(__name__)

import time

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

def LocalMain(spid, save_path) :

    attempts = 0
    while True :
        try :
            logger.debug('initialize the enclave')
            info = pdo_enclave_helper.get_enclave_service_info(spid)

            logger.info('save MR_ENCLAVE and MR_BASENAME to %s', save_path)
            with open(save_path, "w") as file :
                file.write("MRENCLAVE:{0}\n".format(info[0]))
                file.write("BASENAME:{0}\n".format(info[1]))

            sys.exit(0)

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

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

## -----------------------------------------------------------------
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
ContractData = os.environ.get("CONTRACTDATA") or os.path.join(ContractHome, "data")

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def Main() :
    save_path = os.path.realpath(os.path.join(ContractData, "EServiceEnclaveInfo.tmp"))
    spid = os.environ.get("PDO_SPID") if "PDO_SPID" in os.environ else "00000000000000000000000000000000"

    parser = argparse.ArgumentParser()

    parser.add_argument('--spid', help='SPID to generate enclave basename', type=str)
    parser.add_argument('--save', help='Where to save MR_ENCLAVE and BASENAME', type=str)
    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    options = parser.parse_args()

    # Location to save MR_ENCLAVE and MR_BASENAME
    if options.save :
        save_path = options.save

    if options.spid :
        spid = options.spid


    LogConfig = {}
    LogConfig['Logging'] = {
        'LogFile' : '__screen__',
        'LogLevel' : 'INFO'
    }

    if options.logfile :
        LogConfig['Logging']['LogFile'] = options.logfile
    if options.loglevel :
        LogConfig['Logging']['LogLevel'] = options.loglevel.upper()

    plogger.setup_loggers(LogConfig.get('Logging', {}))
    sys.stdout = plogger.stream_to_logger(logging.getLogger('STDOUT'), logging.DEBUG)
    sys.stderr = plogger.stream_to_logger(logging.getLogger('STDERR'), logging.WARN)

    # GO!
    LocalMain(spid, save_path)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
