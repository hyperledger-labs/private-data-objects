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
import pdo.eservice.pdo_enclave as pdo_enclave
import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

def LocalMain(save_path) :
    try :
        logger.debug('initialize the enclave')
        pdo_enclave_helper.get_enclave_service_info()

        logger.info('save MR_ENCLAVE and MR_BASENAME to %s', save_path)
        with open(save_path, "w") as file :
            file.write("MRENCLAVE:" + pdo_enclave.get_enclave_measurement() +"\n")
            file.write("BASENAME:" + pdo_enclave.get_enclave_basename() +"\n")


    except Error as e :
        logger.exception('failed to initialize enclave; %s', e)
        sys.exit(-1)

    sys.exit(0)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

## -----------------------------------------------------------------
ContractHome = os.environ.get("CONTRACTHOME") or os.path.realpath("/opt/pdo")
ContractData = os.environ.get("CONTRACTDATA") or os.path.join(ContractHome, "data")

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def Main() :
    save_path = os.path.realpath(os.path.join(ContractData, "EServiceEnclaveInfo.tmp"))

    parser = argparse.ArgumentParser()

    parser.add_argument('--save', help='Where to save MR_ENCLAVE and BASENAME', type=str)
    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    options = parser.parse_args()

    # Location to save MR_ENCLAVE and MR_BASENAME
    if options.save :
        save_path = options.save

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
    LocalMain(save_path)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
