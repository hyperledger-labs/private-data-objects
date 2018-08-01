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

"""
Enclave service.
"""

import os
import sys
import argparse
import json

import pdo.common.config as pconfig
import pdo.common.keys as keys
import pdo.common.logger as plogger

import pdo.eservice.pdo_helper as pdo_enclave_helper

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

from twisted.web import server, resource, http
from twisted.internet import reactor
from twisted.web.error import Error

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class ContractEnclaveServer(resource.Resource):
    isLeaf = True

    ## -----------------------------------------------------------------
    def __init__(self, config, enclave) :
        self.Config = config

        self.Enclave = enclave
        self.SealedData = enclave.sealed_data
        self.VerifyingKey = enclave.verifying_key
        self.EncryptionKey = enclave.encryption_key
        self.EnclaveID = enclave.enclave_id

        self.RequestMap = {
            'UpdateContractRequest' : self._HandleUpdateContractRequest,
            'EnclaveDataRequest' : self._HandleEnclaveDataRequest,
            'VerifySecretRequest' : self._HandleVerifySecretRequest
        }

    ## -----------------------------------------------------------------
    def ErrorResponse(self, request, response, msg) :
        """
        Generate a common error response for broken requests
        """

        if response > 400 :
            logger.warn(msg)
        elif response > 300 :
            logger.debug(msg)

        request.setResponseCode(response)
        request.setHeader('content-type', 'text/plain')

        result = "" if request.method == 'HEAD' else (msg + '\n')
        return result.encode('utf8')

    ## -----------------------------------------------------------------
    def render_GET(self, request) :
        logger.warn('GET REQUEST: %s', request.uri)
        if request.uri == b'/shutdown' :
            logger.warn('shutdown request received')
            reactor.callLater(1, reactor.stop)
            return ""

        return self.ErrorResponse(request, http.BAD_REQUEST, 'unsupported')

    ## -----------------------------------------------------------------
    def render_POST(self, request) :
        """
        Handle a POST request on the HTTP interface. All message on the
        POST interface are gossip messages that should be relayed into
        the gossip network as is.
        """

        try :
            # process the message encoding
            encoding = request.getHeader('Content-Type')
            data = request.content.getvalue()

            if encoding == 'application/json' :
                # Attempt to decode the data if it is not already a string
                try:
                    data = data.decode('utf-8')
                except AttributeError:
                    pass
                minfo = json.loads(data)
            # elif encoding == 'application/cbor' :
            #     minfo = cbor.loads(data)
            else :
                msg = 'unknown message encoding, {0}'.format(encoding)
                return self.ErrorResponse(request, http.BAD_REQUEST, msg)

        except :
            logger.exception('exception while decoding http request %s', request.path)

            msg = 'unabled to decode incoming request {0}'.format(data)
            return self.ErrorResponse(request, http.BAD_REQUEST, msg)

        operation = minfo.get('operation', '**UNSPECIFIED**')
        if operation not in self.RequestMap :
            msg = 'unknown request {0}'.format(operation)
            return self.ErrorResponse(request, http.BAD_REQUEST, msg)

        # and finally execute the associated method and send back the results
        try :
            logger.debug('received request %s', operation)

            response_dict = self.RequestMap[operation](minfo)
            if encoding == 'application/json' :
                response = json.dumps(response_dict)
            # elif encoding == 'application/cbor' :
            #     response = cbor.dumps(response_dict)

            logger.debug('response[%s]: %s', encoding, response)
            request.setHeader('content-type', encoding)
            request.setResponseCode(http.OK)
            return response.encode('utf8')

        except Error as e :
            #logger.exception('exception while processing request %s', request.path)
            #msg = 'exception while processing request {0}; {1}'.format(request.path, str(e))
            return self.ErrorResponse(request, int(e.status), e.message)

        except :
            logger.exception('unknown exception while processing request %s', request.path)
            msg = 'unknown exception processing http request {0}'.format(request.path)
            return self.ErrorResponse(request, http.BAD_REQUEST, msg)

    ## -----------------------------------------------------------------
    def _HandleUpdateContractRequest(self, minfo) :
        # {
        #     "encrypted_session_key" : <>,
        #     "encrypted_request" : <>
        # }

        try :
            encrypted_session_key = minfo['encrypted_session_key']
            encrypted_request = minfo['encrypted_request']

        except KeyError as ke :
            logger.error('missing field in request: %s', ke)
            raise Error(http.BAD_REQUEST, 'missing field {0}'.format(ke))

        try :
            response = self.Enclave.send_to_contract(
                encrypted_session_key,
                encrypted_request)

            return {'result' : response}

        except :
            logger.exception('api_send_message')
            raise Error(http.BAD_REQUEST, "api_send_message")


    ## -----------------------------------------------------------------
    def _HandleVerifySecretRequest(self, minfo) :
        ## {
        ##    "contract_id" : <>,
        ##    "creator_id" : <>,
        ##    "secrets" : [
        ##        {
        ##            "pspk" : <>,
        ##            "encrypted_secret" : <>
        ##        }
        ##    ]
        ## }
        try :
            contractid = minfo['contract_id']
            creatorid = minfo['creator_id']
            secrets = minfo['secrets']

            # verify the integrity of the secret list
            for secret in secrets :
                assert secret['pspk']
                assert secret['encrypted_secret']

        except KeyError as ke :
            logger.error('missing field in request: %s', ke)
            raise Error(http.BAD_REQUEST, 'missing field {0}'.format(ke))

        try :
            verify_response = self.Enclave.verify_secrets(
                contractid,
                creatorid,
                secrets)

            return dict(verify_response)

        except :
            logger.exception('HandleVerifySecretsRequest')
            raise Error(http.BAD_REQUEST, "HandleVerifySecrets")

    ## -----------------------------------------------------------------
    def _HandleEnclaveDataRequest(self, minfo) :
        response = dict()
        response['verifying_key'] = self.VerifyingKey
        response['encryption_key'] = self.EncryptionKey
        response['enclave_id'] = self.EnclaveID
        return response

# -----------------------------------------------------------------
# sealed_data is base64 encoded string
# -----------------------------------------------------------------
def LoadEnclaveData(enclave_config, txn_keys) :
    data_dir = enclave_config['DataPath']
    basename = enclave_config['BaseName']

    try :
        enclave = pdo_enclave_helper.Enclave.read_from_file(basename, data_dir = data_dir, txn_keys = txn_keys)
    except FileNotFoundError as fe :
        logger.warn("enclave information file missing; {0}".format(fe.filename))
        return None
    except Exception as e :
        logger.error("problem loading enclave information; %s", str(e))
        raise e

    return enclave

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def CreateEnclaveData(enclave_config, ledger_config, txn_keys) :
    logger.warn('unable to locate the enclave data; creating new data')

    # create the enclave class
    try :
        enclave = pdo_enclave_helper.Enclave.create_new_enclave(txn_keys = txn_keys)
    except Exception as e :
        logger.error("unable to create a new enclave; %s", str(e))
        raise e

    # save the data to a file
    data_dir = enclave_config['DataPath']
    basename = enclave_config['BaseName']
    try :
        enclave.save_to_file(basename, data_dir = data_dir)
    except Exception as e :
        logger.error("unable to save new enclave; %s", str(e))
        raise e

    # register the enclave
    try :
        enclave.register_enclave(ledger_config)
    except Exception as e:
        logger.error("unable to register the enclave; %s", str(e))
        raise e

    return enclave

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def RunEnclaveService(config, enclave) :
    httpport = config['EnclaveService']['HttpPort']
    logger.info('service started on port %s', httpport)

    root = ContractEnclaveServer(config, enclave)
    site = server.Site(root)
    reactor.listenTCP(httpport, site)

    try :
        reactor.run()
    except ReactorNotRunning:
        logger.warn('shutdown')
    except :
        logger.warn('shutdown')

    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def LocalMain(config) :
    # enclave configuration is in the 'EnclaveConfig' table
    try :
        logger.debug('initialize the enclave')
        pdo_enclave_helper.initialize_enclave(config.get('EnclaveModule'))
    except Error as e :
        logger.exception('failed to initialize enclave; %s', e)
        sys.exit(-1)

    try :
        enclave_config = config.get('EnclaveData', {})
        ledger_config = config.get('Sawtooth', {})
        key_config = config.get('Key', {})

        try :
            key_file = key_config['FileName']
            key_path = key_config['SearchPath']
            txn_keys = keys.TransactionKeys.read_from_file(key_file, search_path = key_path)
        except Exception as e :
            logger.error('unable to load transaction keys; %s', str(e))
            sys.exit(-1)

        enclave = LoadEnclaveData(enclave_config, txn_keys)
        if enclave is None :
            enclave = CreateEnclaveData(enclave_config, ledger_config, txn_keys)
        assert enclave

        enclave.verify_registration(ledger_config)
    except Error as e:
        logger.exception('failed to initialize enclave; %s', e)
        sys.exit(-1)

    logger.info('start service for enclave\n%s', enclave.verifying_key)
    RunEnclaveService(config, enclave)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

## -----------------------------------------------------------------
ContractHost = os.environ.get("HOSTNAME", "localhost")
ContractHome = os.environ.get("CONTRACTHOME") or os.path.realpath("/opt/pdo")
ContractEtc = os.environ.get("CONTRACTETC") or os.path.join(ContractHome, "etc")
ContractKeys = os.environ.get("CONTRACTKEYS") or os.path.join(ContractHome, "keys")
ContractLogs = os.environ.get("CONTRACTLOGS") or os.path.join(ContractHome, "logs")
ContractData = os.environ.get("CONTRACTDATA") or os.path.join(ContractHome, "data")
LedgerURL = os.environ.get("LEDGER_URL", "http://127.0.0.1:8008/")
ScriptBase = os.path.splitext(os.path.basename(sys.argv[0]))[0]

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
    conffiles = [ 'eservice.toml' ]
    confpaths = [ ".", "./etc", ContractEtc ]

    parser = argparse.ArgumentParser()

    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='configuration file', nargs = '+')

    parser.add_argument('--identity', help='Identity to use for the process', required = True, type = str)

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    parser.add_argument('--http', help='Port on which to run the http server', type=int)
    parser.add_argument('--ledger', help='Default url for connection to the ledger', type=str)

    parser.add_argument('--enclave-data', help='Name of the file containing enclave sealed storage', type=str)
    parser.add_argument('--enclave-save', help='Name of the directory where enclave data will be save', type=str)
    parser.add_argument('--enclave-path', help='Directories to search for the enclave data file', type=str, nargs = '+')

    options = parser.parse_args()

    # first process the options necessary to load the default configuration
    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

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

    # set up the ledger configuration
    if config.get('Sawtooth') is None :
        config['Sawtooth'] = {
            'LedgerURL' : 'http://localhost:8008',
        }
    if options.ledger :
        config['Sawtooth']['LedgerURL'] = options.ledger

    # set up the enclave service configuration
    if config.get('EnclaveService') is None :
        config['EnclaveService'] = {
            'HttpPort' : 7101,
            'Host' : 'localhost',
            'Identity' : 'enclave'
        }
    if options.http :
        config['EnclaveService']['HttpPort'] = options.http

    if config.get('EnclaveData') is None :
        config['EnclaveData'] = {
            'FileName' : 'enclave.data',
            'SavePath' : './data',
            'SearchPath' : [ '.', './data' ]
        }
    if options.enclave_data :
        config['EnclaveData']['FileName'] = options.enclave_data
    if options.enclave_save :
        config['EnclaveData']['SavePath'] = options.enclave_save
    if options.enclave_path :
        config['EnclaveData']['SearchPath'] = options.enclave_path

    # GO!
    LocalMain(config)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
