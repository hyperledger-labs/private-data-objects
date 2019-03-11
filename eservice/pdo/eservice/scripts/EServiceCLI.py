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

import time

import pdo.common.config as pconfig
import pdo.common.keys as keys
import pdo.common.logger as plogger

import pdo.eservice.pdo_helper as pdo_enclave_helper
from pdo.eservice.wsgi.info import InfoApp
from pdo.eservice.wsgi.invoke import InvokeApp
from pdo.eservice.wsgi.verify import VerifyApp

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
request_identifier = 0

from twisted.web import http
from twisted.web.resource import Resource, NoResource
from twisted.web.server import Site, NOT_DONE_YET
from twisted.python.threadpool import ThreadPool
from twisted.internet import reactor, defer
from twisted.internet.threads import deferToThread
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.error import ConnectionDone
from twisted.web.wsgi import WSGIResource

## ----------------------------------------------------------------
def ErrorResponse(request, error_code, msg) :
    """Generate a common error response for broken requests
    """

    result = ""
    if request.method != 'HEAD' :
        result = msg + '\n'
        result = result.encode('utf8')

    request.setResponseCode(error_code)
    request.setHeader(b'Content-Type', b'text/plain')
    request.setHeader(b'Content-Length', len(result))
    request.write(result)

    try :
        request.finish()
    except :
        logger.exception("exception during request finish")
        raise

    return request

## ----------------------------------------------------------------
def BusyResponse(request) :
    """Generate a common response for busy server, in theory the
    retry-after is a number of seconds that the client should
    wait; there is nothing particularly special about 1 just
    that we want the client to retransmit, hopefully at a better
    time.
    """

    result = b'BUSY'

    request.setResponseCode(429)          # too many requess
    request.setHeader('Retry-After', 1)   # wait 1 second for retry
    request.setHeader(b'Content-Type', b'text/plain')
    request.setheader(b'Content-Length', len(result))
    request.write(result)

    return request

## -----------------------------------------------------------------
def UnpackRequest(request) :
    """Unpack a JSON request that has been received; this procedure
    is really about making sure that the bytes are in a string format
    that will work across python versions.
    """
    encoding = request.getHeader('Content-Type')
    if encoding != 'application/json' :
        msg = 'unknown message encoding, {0}'.format(encoding)
        raise Exception(msg)

    # Attempt to decode the data if it is not already a string
    try :
        data = request.content.getvalue().decode('utf8')
    except AttributeError:
        pass

    try :
        return json.loads(data)
    except Exception as e :
        msg = 'failed to unpack JSON request'
        raise Exception(msg)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class CommonResource(Resource) :

    ## -----------------------------------------------------------------
    def __init__(self, enclave) :
        Resource.__init__(self)
        self.enclave = enclave

    ## -----------------------------------------------------------------
    def _handle_connection_lost_(self, identifier, reason) :
        msg = ''
        if reason is not None :
            if reason.check(ConnectionDone) :
                logger.debug("[%05d] connection closed: %s", identifier, msg)
                return
            msg = reason.getErrorMessage()

        logger.warn("[%05d] connection lost: %s", identifier, msg)

    ## -----------------------------------------------------------------
    def _handle_error_(self, identifier, failure) :
        logger.warn("[%05d] an error occurred: %s", identifier, failure.getErrorMessage())
        f = failure.trap(Error, Exception)

    ## -----------------------------------------------------------------
    def _defer_request_(self, handler, request) :
        threadpool = reactor.getThreadPool()
        if len(threadpool.working) > 8 :
            return BusyResponse(request)

        global request_identifier
        request_identifier += 1
        request.request_identifier = request_identifier
        logger.debug('[%05d] start request: %s:%s', request.request_identifier, request.client.host, request.client.port)

        request.notifyFinish().addErrback(lambda r : self._handle_connection_lost_(request.request_identifier, r))

        d = deferToThread(handler, request)
        d.addErrback(lambda r : self._handle_error_(request.request_identifier, r))

        return NOT_DONE_YET


## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class ShutdownResource(Resource) :
    isLeaf = True

    ## -----------------------------------------------------------------
    def __init__(self) :
        Resource.__init__(self)

    ## -----------------------------------------------------------------
    def render_GET(self, request) :
        logger.warn('shutdown request received')
        reactor.callLater(1, reactor.stop)

        return ErrorResponse(request, http.NO_CONTENT, "shutdown")

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def StartEnclaveService(http_host, http_port, enclave, storage_url) :
    logger.info('service started on port %s', http_port)

    thread_pool = ThreadPool(maxthreads=8)
    thread_pool.start()
    reactor.addSystemEventTrigger('before', 'shutdown', thread_pool.stop)

    root = Resource()
    root.putChild(b'shutdown', ShutdownResource())
    root.putChild(b'info', WSGIResource(reactor, thread_pool, InfoApp(enclave, storage_url)))
    root.putChild(b'invoke', WSGIResource(reactor, thread_pool, InvokeApp(enclave)))
    root.putChild(b'verify', WSGIResource(reactor, thread_pool, VerifyApp(enclave)))

    # root.putChild(b'invoke', InvokeResource(enclave))
    # root.putChild(b'verify', VerifyResource(enclave))
    # root.putChild(b'info', InfoResource(enclave, storage_url))

    site = Site(root, timeout=60)
    site.displayTracebacks = True

    reactor.suggestThreadPoolSize(10)

    endpoint = TCP4ServerEndpoint(reactor, http_port, backlog=32, interface=http_host)
    endpoint.listen(site)

    #reactor.listenTCP(http_port, site, interface=http_host)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def RunService() :
    @defer.inlineCallbacks
    def shutdown_twisted():
        logger.info("Stopping Twisted")
        yield reactor.callFromThread(reactor.stop)

    reactor.addSystemEventTrigger('before', 'shutdown', shutdown_twisted)

    try :
        reactor.run()
    except ReactorNotRunning:
        logger.warn('shutdown')
    except :
        logger.warn('shutdown')

    pdo_enclave_helper.shutdown_enclave()
    sys.exit(0)

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
def LocalMain(config) :
    # load and initialize the enclave library
    try :
        logger.debug('initialize the enclave')
        pdo_enclave_helper.initialize_enclave(config)
    except Exception as e :
        logger.exception('failed to initialize enclave; %s', e)
        sys.exit(-1)

    # create the sawtooth transaction keys needed to register the enclave
    try :
        key_config = config['Key']
        key_file = key_config['FileName']
        key_path = key_config['SearchPath']
        txn_keys = keys.TransactionKeys.read_from_file(key_file, search_path = key_path)
    except KeyError as ke :
        logger.error('missing configuration for %s', str(ke))
        sys.exit(-1)
    except Exception as e :
        logger.error('unable to load transaction keys; %s', str(e))
        sys.exit(-1)

    # create or load the enclave data
    try :
        enclave_config = config['EnclaveData']
        ledger_config = config['Sawtooth']
        enclave = LoadEnclaveData(enclave_config, txn_keys)
        if enclave is None :
            enclave = CreateEnclaveData(enclave_config, ledger_config, txn_keys)
            assert enclave

        enclave.verify_registration(ledger_config)
    except KeyError as ke :
        logger.error('missing configuration for %s', str(ke))
        sys.exit(-1)
    except Exception as e :
        logger.error('failed to initialize the enclave; %s', str(e))
        sys.exit(-1)

    # set up the handlers for the enclave service
    try :
        http_port = config['EnclaveService']['HttpPort']
        http_host = config['EnclaveService']['Host']
        storage_url = config['StorageService']['URL']
        StartEnclaveService(http_host, http_port, enclave, storage_url)
    except KeyError as ke :
        logger.error('missing configuration for %s', str(ke))
        sys.exit(-1)
    except Exception as e:
        logger.exception('failed to start the enclave service; %s', e)
        sys.exit(-1)

    # and run the service
    RunService()

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

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    parser.add_argument('--http', help='Port on which to run the http server', type=int)
    parser.add_argument('--ledger', help='Default url for connection to the ledger', type=str)

    parser.add_argument('--block-store', help='Name of the file where blocks are stored', type=str)
    parser.add_argument('--sservice-url', help='URL for the associated storage service', type=str)

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

    # set up the enclave service configuration
    if config.get('StorageService') is None :
        config['StorageService'] = {
            'BlockStore' : os.path.join(ContractData, options.identity + '.mdb'),
            'URL' : 'http://localhost:7201'
        }
    if options.block_store :
        config['StorageService']['BlockStore'] = options.block_store
    if options.sservice_url :
        config['StorageService']['URL'] = options.sservice_url

    if config['StorageService'].get('URL') is None :
        host = config['StorageService'].get('Host','localhost')
        port = config['StorageService'].get('HttpPort',7201)
        config['StorageService']['URL'] = "http://{0}:{1}".format(host, port)

    # GO!
    LocalMain(config)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
