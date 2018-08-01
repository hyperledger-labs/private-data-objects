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
Provisioning service

"""

import os, sys
import sysconfig
import traceback
import logging
import argparse
import json
import errno
import hashlib
import socket

from sawtooth.helpers.pdo_connect import PdoClientConnectHelper
from sawtooth.helpers.pdo_connect import PdoRegistryHelper
from sawtooth.helpers.pdo_connect import ClientConnectException

import pdo.common.crypto as pcrypto
import pdo.common.config as pconfig
import pdo.common.logger as plogger
import pdo.common.utility as putils

import pdo.pservice.pdo_helper as pdo_enclave_helper
import pdo.pservice.pdo_enclave as pdo_enclave


logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

from twisted.web import server, resource, http
from twisted.internet import reactor
from twisted.web.error import Error

import base64


## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class ProvisioningServer(resource.Resource):
    isLeaf = True

    ## -----------------------------------------------------------------
    def __init__(self, config, enclave) :

        self.Enclave = enclave
        self.SealedData = enclave.sealed_data
        self.PSPK = enclave.verifying_key # Enclave public signing key
        self.EncryptionKey = enclave.encryption_key # Enclave public encryption key
        self.EnclaveID = enclave.enclave_id

        self.__registry_helper = PdoRegistryHelper(config['Sawtooth']['LedgerURL'])

        self.secrets_file_path = config['SecretsFilePath']
        self.secret_length = 16

        self.RequestMap = {
            'secretRequest' : self._secretreq,
            'dataRequest' : self._datareq,
        }


    ## -----------------------------------------------------------------
    def _GetContractSecret(self, contracttxnid) :
        """
        Retrieve or create the secret for a particular contract, returned in
        raw format
        """

        file_secrets = dict()
        with open(self.secrets_file_path, "r") as f:
            for line in f:
                key, val = line.partition(":")[::2]
                file_secrets[key.strip()] = val.strip()

        contracttxnid = hashlib.sha256(contracttxnid.encode()).hexdigest()

        # If secret already exists, return it, otherwise create, store, and return a new secret
        if contracttxnid in file_secrets:
            sealed_secret = file_secrets[contracttxnid]
            logger.debug('Secret for contract %s found', contracttxnid)
        else:
            sealed_secret = self.Enclave.create_secret(self.secret_length)["sealed_secret"]
            file_secrets[contracttxnid] = sealed_secret
            logger.debug('Creating new Secret for contract %s', contracttxnid)
            with open(self.secrets_file_path, "w") as f:
                for key in file_secrets:
                    f.write(key + ' : ' + file_secrets[key] + "\n")

        return sealed_secret

    ## -----------------------------------------------------------------
    def ErrorResponse(self, request, response, *msgargs) :
        """
        Generate a common error response for broken requests
        """
        request.setResponseCode(response)

        msg = msgargs[0].format(*msgargs[1:])
        if response > 400 :
            logger.warn(msg)
        elif response > 300 :
            logger.debug(msg)

        return "" if request.method == 'HEAD' else (msg + '\n')

    ## -----------------------------------------------------------------
    def _datareq(self, minfo) :
        logger.debug('Got request for public key data')

        # create the response
        response = dict()
        response['pspk'] = self.PSPK

        return response

    ## -----------------------------------------------------------------
    def _secretreq(self, minfo) :
        # unpack the request
        try:
            enclave_id = minfo['enclave_id']
            contract_id = minfo['contract_id']
            opk = minfo['opk']
            signature = minfo['signature']

        except KeyError as ke:
            raise Error(http.BAD_REQUEST, 'missing required field {0}'.format(ke))

        logger.debug('request for key for contract %s, enclave %s', contract_id, enclave_id)

        # verify the signature, that is, make sure that the request was really signed by opk
        try:
            opkkey = pcrypto.SIG_PublicKey(opk)
            opkkey.VerifySignature(pcrypto.string_to_byte_array(enclave_id + contract_id), pcrypto.hex_to_byte_array(signature))
        except:
            logger.warn("Signature verification failed")
            raise Error(http.BAD_REQUEST, 'Signature Mismatch')

        # Get enclave state
        try:
            logger.debug('retrieve information for enclave %s', enclave_id)
            enclave_info = self.__registry_helper.get_enclave_dict(enclave_id)
            logger.debug("enclave information retrieved: %s", enclave_info)
        except BaseException as err:
            logger.warn('exception occurred when getting ledger information for enclave %s; %s', enclave_id, str(err))
            raise Error(http.BAD_REQUEST, 'could not retrieve enclave state; {0}'.format(err))
        except ClientConnectException as err:
            logger.warn('client exception occurred when getting ledger information for enclave %s; %s', enclave_id, str(err))
            raise Error(http.BAD_REQUEST, 'could not retrieve enclave state; {0}'.format(err))

        # Get contract state
        try:
            logger.debug('retrieve information for contract <%s>', contract_id)
            contract_info = self.__registry_helper.get_contract_dict(contract_id)
            logger.debug("contract_info from ledger: %s", contract_info)
        except BaseException as err:
            logger.warn('exception occurred when getting ledger information for contract %s; %s', contract_id, str(err))
            raise Error(http.BAD_REQUEST, 'could not retrieve contract state; {0}'.format(err))
        except ClientConnectException as err:
            logger.warn('client exception occurred when getting ledger information for contract %s; %s', contract_id, str(err))
            raise Error(http.BAD_REQUEST, 'could not retrieve contract state; {0}'.format(err))

        # make sure that the signer of this request is really the owner of the contract
        try :
            # make sure that the signer of this request is really the owner of the contract
            # PdoContractInfo.pdo_contract_creator_pem_key is the VerifyingKey
            logger.debug("Contract creator's public key: %s", contract_info['pdo_contract_creator_pem_key'])
            logger.debug("Expected public key: %s", opk)
            assert contract_info['pdo_contract_creator_pem_key'] == opk
        except :
            logger.error('request to create secret did not come from the contract owner; %s != %s', contracttxn.OriginatorID, opk)
            raise Error(http.NOT_ALLOWED, 'operation not allowed for {0}'.format(opk))

        # make sure the provisioning service is allowed to access contract by the checking the list of allowed provisioning services
        try :
            logger.debug("Contract allowed service ids: %s", contract_info['provisioning_service_ids'])
            logger.debug("Expected provisioning service id: %s", self.PSPK)
            assert self.PSPK in contract_info['provisioning_service_ids']
        except :
            logger.error('This Pservice is not the list of allowed provisioning services, PSerivce ID: %s', self.PSPK)
            raise Error(http.NOT_ALLOWED, 'operation not allowed for {0}'.format(self.PSPK))

        # retrieve the sealed secret
        sealed_secret = self._GetContractSecret(contract_id)

        logger.debug("Enclave Info: %s", str(enclave_info))

        # Generate Secret for Contract Enclave, signs unsealed secret with contract enclave encryption key
        esecret = self.Enclave.generate_enclave_secret(
            self.SealedData,
            sealed_secret,
            contract_id,
            opk,
            json.dumps(enclave_info),
            )["enclave_secret"]

        logger.debug("Encrypted secret for contract %s: %s", contract_id, esecret)

        # create the response
        response = dict()
        response['pspk'] = self.PSPK
        response['encrypted_secret'] = esecret

        logger.info('created secret for contract %s and enclave %s', contract_id, enclave_id)
        return response

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
        Handle a POST request on the HTTP interface. All message on the POST interface are
        gossip messages that should be relayed into the gossip network as is.
        """

        # process the message encoding
        encoding = request.getHeader('Content-Type')
        data = request.content.getvalue()
        data = data.decode('utf-8')

        try :
            if encoding == 'application/json' :
                minfo = json.loads(data)
            else :
                logger.warn('unknown message encoding')
                return self.ErrorResponse(request, http.BAD_REQUEST, 'unknown message encoding, {0}', encoding)

            reqtype = minfo.get('reqType', '**UNSPECIFIED**')
            if reqtype not in self.RequestMap :
                logger.warn('unknown message type')
                return self.ErrorResponse(request, http.BAD_REQUEST, 'received request for unknown message type')

        except :
            logger.warn('exception while decoding http request %s; %s', request.path, traceback.format_exc(20))
            return self.ErrorResponse(request, http.BAD_REQUEST, 'unabled to decode incoming request {0}', data)

        # and finally execute the associated method and send back the results
        try :
            response = json.dumps(self.RequestMap[reqtype](minfo))

            request.responseHeaders.addRawHeader("content-type", encoding)
            logger.debug('Return Response: %s', response)
            return response.encode('utf-8')

        except Error as e :
            logger.warn('exception while processing request; %s', str(e))
            # return self.ErrorResponse(request, int(e.status), 'exception while processing request {0}; {1}', request.path, str(e))
            return self.ErrorResponse(request, int(e.status), 'exception while processing request')

        except :
            logger.warn('exception while processing http request %s; %s', request.path, traceback.format_exc(20))
            return self.ErrorResponse(request, http.BAD_REQUEST, 'error processing http request {0}', request.path)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def RunProvisioningService(config, enclave) :
    httpport = config['ProvisioningService']['HttpPort']
    logger.info('Provisioning Service started on port %s', httpport)

    root = ProvisioningServer(config, enclave)
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
def GetSecretsFilePath(data_config) :
    """
    Return secrets data file location. If it doesnt exist, creates a new one in the 'DefaultPath' specified in config file
    """

    try :
        data_file_path = putils.find_file_in_path(data_config['FileName'], data_config['SearchPath'])
        return data_file_path
    except FileNotFoundError as e :
        logger.warn('provisioning secrets data file missing')

    default_file_path = os.path.realpath(os.path.join(data_config['DefaultPath'], data_config['FileName']))

    try:
        os.makedirs(os.path.dirname(default_file_path), exist_ok=True)
        open(default_file_path, "w").close()
        logger.debug('save secrets data file to %s', default_file_path)
        return default_file_path
    except Exception as e:
        logger.warning('Error creating new secrets data file; %s', str(e))
        raise e

    return None

# -----------------------------------------------------------------
# sealed_data is base64 encoded string
# -----------------------------------------------------------------
def LoadEnclaveData(enclave_config) :
    data_dir = enclave_config['DataPath']
    basename = enclave_config['BaseName']

    try :
        enclave = pdo_enclave_helper.Enclave.read_from_file(basename, data_dir = data_dir)
    except FileNotFoundError as fe :
        logger.warn("enclave information file missing; {0}".format(fe.filename))
        return None
    except Exception as e :
        logger.error("problem loading enclave information; %s", str(e))
        raise e

    return enclave

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def CreateEnclaveData(enclave_config) :
    logger.warn('unable to locate the enclave data; creating new data')

    # create the enclave class
    try :
        enclave = pdo_enclave_helper.Enclave.create_new_enclave()
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

    return enclave

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def LocalMain(config) :

    try:
        # enclave configuration is in the 'EnclaveConfig' table
        try :
            logger.debug('initialize the enclave')
            pdo_enclave_helper.initialize_enclave(config.get('EnclaveModule'))
            logger.info('EnclaveModule; %s', config.get('EnclaveModule'))
        except Error as e :
            logger.exception('failed to initialize enclave; %s', e)
            sys.exit(-1)

        try :
            data_config = config.get('ProvisioningData', {})
            config["SecretsFilePath"] = GetSecretsFilePath(data_config)
        except Exception as e :
            logger.warning('Unable to locate or create provisioning secrets data file')
            sys.exit(-1)

        enclave_config = config.get('EnclaveData', {})
        enclave = LoadEnclaveData(enclave_config)
        if enclave is None :
            enclave = CreateEnclaveData(enclave_config)
        assert enclave
    except Error as e:
        logger.exception('failed to initialize enclave; %s', e)
        sys.exit(-1)

    RunProvisioningService(config, enclave)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

## -----------------------------------------------------------------
ContractHost = os.environ.get("HOSTNAME", "localhost")
ContractHome = os.environ.get("CONTRACTHOME") or os.path.realpath(".")
ContractEtc = os.environ.get("CONTRACTETC") or os.path.join(ContractHome, "etc")
ContractKeys = os.environ.get("CONTRACTKEYS") or os.path.join(ContractHome, "keys")
ContractLogs = os.environ.get("CONTRACTLOGS") or os.path.join(ContractHome, "logs")
ContractData = os.environ.get("CONTRACTDATA") or os.path.join(ContractHome, "data")
LedgerURL = os.environ.get("LEDGER_URL", "http://127.0.0.1:8008/")
ScriptBase = os.path.splitext(os.path.basename(sys.argv[0]))[0]

config_map = {
    'base' : ScriptBase,
    'etc'  : ContractEtc,
    'home' : ContractHome,
    'host' : ContractHost,
    'keys' : ContractKeys,
    'logs' : ContractLogs,
    'data' : ContractData,
    'ledger' : LedgerURL
}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def Main() :
    # parse out the configuration file first
    conffiles = ['pservice.toml' ]
    confpaths = [ '.', './etc', ContractEtc ]

    parser = argparse.ArgumentParser()

    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='configuration file', nargs = '+')

    parser.add_argument('--identity', help='Identity to use for the process', required = True, type = str)

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    parser.add_argument('--http', help='Port on which to run the http server', type=int)
    parser.add_argument('--ledger', help='Default url for connection to the ledger', type=str)

    parser.add_argument('--provisioning-save', help='Directory where data files will be stored', type=str)
    parser.add_argument('--provisioning-path', help='Directories to search for the enclave data file', type=str, nargs='+')
    parser.add_argument('--provisioning-data', help='Name of the file containing enclave sealed storage', type=str)

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

    # set up the provisioning service configuration
    if config.get('ProvisioningService') is None :
        config['ProvisioningService'] = {
            'HttpPort' : 7001,
            'Host' : 'localhost',
            'Identity' : 'provisioning'
        }
    if options.http :
        config['ProvisioningService']['HttpPort'] = options.http

    if config.get('ProvisioningData') is None :
        config['ProvisioningData'] = {
            'FileName' : 'provisioning.data',
            'SavePath' : './data',
            'SearchPath' : [ '.', './data' ]
        }
    if options.provisioning_data :
        config['ProvisioningData']['FileName'] = options.provisioning_data
    if options.provisioning_save :
        config['ProvisioningData']['SavePath'] = options.provisioning_save
    if options.provisioning_path :
        config['ProvisioningData']['SearchPath'] = options.provisioning_path

    # GO!
    LocalMain(config)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
