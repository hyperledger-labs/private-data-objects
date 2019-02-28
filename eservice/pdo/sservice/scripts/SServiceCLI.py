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

"""
Storage service.
"""

import os
import sys
import argparse

import base64
import hashlib
import json
import time

from pdo.sservice.block_store_manager import BlockStoreManager

import pdo.common.config as pconfig
import pdo.common.keys as keys
import pdo.common.logger as plogger

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

from twisted.web import http
from twisted.web.server import Site
from twisted.web.resource import Resource, NoResource
from twisted.internet import reactor, defer, task
from twisted.internet.threads import deferToThread
from twisted.web.server import NOT_DONE_YET
from twisted.web.error import Error
from twisted.python.threadpool import ThreadPool

## ----------------------------------------------------------------
def ErrorResponse(request, error_code, msg) :
    """
    Generate a common error response for broken requests
    """

    if error_code > 400 :
        logger.warn(msg)
    elif error_code > 300 :
        logger.debug(msg)

    result = "" if request.method == 'HEAD' else (msg + '\n')

    request.setResponseCode(error_code)
    request.setHeader('content-type', 'text/plain')
    request.write(result.encode('utf8'))

    return request

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class CommonResource(Resource) :

    ## -----------------------------------------------------------------
    def __init__(self, block_store) :
        Resource.__init__(self)
        self.block_store = block_store

    ## -----------------------------------------------------------------
    def _handle_error_(self, failure) :
        f = failure.trap(Exception)
        logger.warn("an error occurred (%s): %s", type(self).__name__, failure.value.args)

    ## -----------------------------------------------------------------
    def _handle_done_(self, request) :
        request.finish()

    ## -----------------------------------------------------------------
    def _defer_request_(self, handler, request) :
        d = deferToThread(handler, request)
        d.addErrback(self._handle_error_)
        d.addCallback(self._handle_done_)

        return NOT_DONE_YET

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class ListBlocksResource(CommonResource) :
    isLeaf = True

    ## -----------------------------------------------------------------
    def __init__(self, block_store) :
        CommonResource.__init__(self, block_store)

    ## -----------------------------------------------------------------
    def _handle_request_(self, request) :
        try :
            block_ids = self.block_store.list_blocks(encoding='b64')
            result = json.dumps(block_ids).encode()

            request.setResponseCode(http.OK)
            request.setHeader('content-type', 'application/json')
            request.write(result)

            return request

        except Exception as e :
            logger.error("unknown exception (ListBlocks); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while processing list blocks request")

    ## -----------------------------------------------------------------
    def render_GET(self, request) :
        return self._defer_request_(self._handle_request_, request)


## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class GetBlockResource(CommonResource) :
    isLeaf = True

    ## -----------------------------------------------------------------
    def __init__(self, block_store, block_id) :
        CommonResource.__init__(self, block_store)
        self.block_id = block_id

    ## -----------------------------------------------------------------
    def _handle_get_request_(self, request) :
        try :
            block_data = self.block_store.get_block(self.block_id, encoding='b64')
            if block_data is None :
                return ErrorResponse(request, http.NOT_FOUND, "unknown block; {0}".format(self.block_id))

            request.setResponseCode(http.OK)
            request.setHeader('content-type', 'application/octet-stream')
            request.write(block_data)

            return request

        except Exception as e :
            logger.error("unknown exception (BlockGet); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST,
                                 "unknown exception while processing get block request; {0}".format(self.block_id))

    ## -----------------------------------------------------------------
    def render_GET(self, request) :
        return self._defer_request_(self._handle_get_request_, request)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class CheckBlocksResource(CommonResource) :
    isLeaf = True

    ## -----------------------------------------------------------------
    def __init__(self, block_store) :
        CommonResource.__init__(self, block_store)

    ## -----------------------------------------------------------------
    def _handle_request_(self, request) :
        try :
            # process the message encoding
            encoding = request.getHeader('Content-Type')
            data = request.content.getvalue()

            if encoding != 'application/json' :
                msg = 'unknown message encoding, {0}'.format(encoding)
                return ErrorResponse(request, http.BAD_REQUEST, msg)

            # Attempt to decode the data if it is not already a string
            try:
                data = data.decode('utf-8')
            except AttributeError:
                pass

            block_ids = json.loads(data)

        except Exception as e :
            logger.error("unknown exception unpacking request (CheckBlock); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while unpacking block status request")

        try :
            block_status_list = self.block_store.check_blocks(block_ids, encoding='b64')

        except Exception as e :
            logger.error("unknown exception computing status (CheckBlock); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while computing block status")

        try :
            result = json.dumps(block_status_list).encode()

            request.setResponseCode(http.OK)
            request.setHeader('content-type', 'application/json')
            request.write(result)

            return request

        except Exception as e :
            logger.error("unknown exception packing response (CheckBlock); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while packing response")

    ## -----------------------------------------------------------------
    def render_POST(self, request) :
        return self._defer_request_(self._handle_request_, request)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class StoreBlocksResource(CommonResource) :
    isLeaf = True

    ## -----------------------------------------------------------------
    def __init__(self, block_store) :
        CommonResource.__init__(self, block_store)

    ## -----------------------------------------------------------------
    def block_data_iterator(self, block_ids, blocks) :
        """create an iterator for the blocks in the request
        """
        for block_id in block_ids :
            yield blocks[block_id.encode('utf8')][0]

    ## -----------------------------------------------------------------
    def _handle_request_(self, request) :
        try :
            data = request.args[b'operation'][0]

            try:
                data = data.decode('utf-8')
            except AttributeError:
                pass

            minfo = json.loads(data)
            block_ids = minfo['block_ids']
            expiration = minfo['expiration']

        except Exception as e :
            logger.error("unknown exception unpacking request (BlockStore); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while unpacking block store request")

        try :
            # block_list will be an iterator for blocks in the request, this prevents
            # the need to make a copy of the data blocks
            block_list = self.block_data_iterator(block_ids, request.args)
            raw_result = self.block_store.store_blocks(block_list, expiration=expiration, encoding='b64')

        except Exception as e :
            logger.error("unknown exception (BlockStore); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while storing blocks")

        try :
            result = json.dumps(raw_result).encode('utf8')

            request.setResponseCode(http.OK)
            request.setHeader('content-type', 'application/json')
            request.write(result)

            return request

        except Exception as e :
            logger.error("unknown exception packing response (BlockStore); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while packing response")

    ## -----------------------------------------------------------------
    def render_POST(self, request) :
        return self._defer_request_(self._handle_request_, request)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class BlockResource(CommonResource) :

    ## -----------------------------------------------------------------
    def __init__(self, block_store) :
        CommonResource.__init__(self, block_store)

    ## -----------------------------------------------------------------
    def getChild(self, name, request) :
        if name == b'list' :
            return ListBlocksResource(self.block_store)
        elif name == b'check' :
            return CheckBlocksResource(self.block_store)
        elif name == b'store' :
            return StoreBlocksResource(self.block_store)
        elif name is not None :
            return GetBlockResource(self.block_store, name)
        else :
            return NoResource()

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class InfoResource(CommonResource) :
    isLeaf = True

    ## -----------------------------------------------------------------
    def __init__(self, block_store) :
        CommonResource.__init__(self, block_store)

    ## -----------------------------------------------------------------
    def _handle_request_(self, request) :

        try :
            response = self.block_store.get_service_info()
            result = json.dumps(response).encode()

        except Exception as e :
            logger.error("unknown exception (Info); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while processing info request")

        request.setResponseCode(http.OK)
        request.setHeader('content-type', 'application/json')
        request.write(result)

        return request

    ## -----------------------------------------------------------------
    def render_GET(self, request) :
        return self._defer_request_(self._handle_request_, request)

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

        ErrorResponse(request, http.NO_CONTENT, "shutdown")
        request.finish()


## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class ContractStorageServer(Resource) :
    ## -----------------------------------------------------------------
    def __init__(self, block_store) :
        Resource.__init__(self)
        self.block_store = block_store

    ## -----------------------------------------------------------------
    def getChild(self, name, request) :
        if name == b'block' :
            return BlockResource(self.block_store)
        elif name == b'info' :
            return InfoResource(self.block_store)
        elif name == b'shutdown' :
            return ShutdownResource()
        else :
            return NoResource()

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
def GarbageCollector(block_store) :
    logger.debug('run the garbage collector')
    try :
        block_store.expire_blocks()
    except Exception as e :
        logger.error('garbage collection failed; %s', str(e))
        return

def StartGarbageCollector(block_store, gcinterval) :
    loop = task.LoopingCall(GarbageCollector, block_store)
    loopDeferred = loop.start(gcinterval)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
def StartStorageService(http_host, http_port, block_store) :
    logger.info('service started on port %s', http_port)

    root = ContractStorageServer(block_store)
    site = Site(root)

    threadpool = reactor.getThreadPool()
    threadpool.start()
    threadpool.adjustPoolsize(8, 100) # Min & Max number of request to service at a time
    logger.info('# of workers: %d', threadpool.workers)

    reactor.listenTCP(http_port, site, interface=http_host)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
def RunService(block_store) :

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

    # sync and close the database
    block_store.close()

    sys.exit(0)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def LocalMain(config) :
    try :
        key_config = config.get('Key', {})

        try :
            key_file = key_config['FileName']
            key_path = key_config['SearchPath']
            service_keys = keys.ServiceKeys.read_from_file(key_file, search_path = key_path)
        except KeyError as ke :
            logger.error('missing configuration for Key.%s', str(ke))
            sys.exit(-1)
        except Exception as e :
            logger.error('unable to load transaction keys; %s', str(e))
            sys.exit(-1)

        service_config = config.get('StorageService', {})

        try :
            gcinterval = service_config['GarbageCollectionInterval']
            if gcinterval < 0 :
                gcinterval = 0            # gcinterval 0 means don't run the garbage collector

            http_port = service_config['HttpPort']
            http_host = service_config['Host']

            create = config.get('create', False)
            block_store_file = service_config['BlockStore']
            block_store = BlockStoreManager(block_store_file, service_keys=service_keys, create_block_store=create)

        except KeyError as ke :
            logger.error('missing configuration for StorageService.%s', str(ke))
            sys.exit(-1)
        except Exception as e :
            logger.error('unable to open the block store; %s', str(e))
            sys.exit(-1)

        try :
            if gcinterval > 0 :
                StartGarbageCollector(block_store, gcinterval)
            StartStorageService(http_host, http_port, block_store)
        except Exception as e :
            logger.error('failed to start services; %s', str(e))
            sys.exit(-1)

    except Error as e:
        logger.exception('failed to initialize the storage service; %s', e)
        sys.exit(-1)

    RunService(block_store)

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
    conffiles = [ 'sservice.toml' ]
    confpaths = [ ".", "./etc", ContractEtc ]

    parser = argparse.ArgumentParser()

    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='directory to search for configuration files', nargs = '+')

    parser.add_argument('--identity', help='Identity to use for the process', required = True, type = str)

    parser.add_argument('--key-dir', help='Directories to search for key files', nargs='+')
    parser.add_argument('--data-dir', help='Path for storing generated files', type=str)

    parser.add_argument('--gc-interval', help='Number of seconds between garbage collection', type=int)
    parser.add_argument('--block-store', help='Name of the file where blocks are stored', type=str)
    parser.add_argument('--create', help='Create the blockstore if it does not exist', action='store_true')
    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    parser.add_argument('--http', help='Port on which to run the http server', type=int)

    options = parser.parse_args()

    # first process the options necessary to load the default configuration
    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    global config_map
    config_map['identity'] = options.identity
    if options.data_dir :
        config_map['data'] = options.data_dir

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

    if options.create :
        config['create'] = True

    # set up the key search paths
    if config.get('Key') is None :
        config['Key'] = {
            'SearchPath' : ['.', './keys', ContractKeys],
            'FileName' : options.identity + ".pem"
        }
    if options.key_dir :
        config['Key']['SearchPath'] = options.key_dir

    # set up the enclave service configuration
    if config.get('StorageService') is None :
        config['StorageService'] = {
            'HttpPort' : 7201,
            'Host' : 'localhost',
            'Identity' : options.identity,
            'BlockStore' : os.path.join(ContractData, options.identity + '.mdb'),
            'GarbageCollectionInterval' : 10
        }
    if options.http :
        config['StorageService']['HttpPort'] = options.http

    if options.block_store :
        config['StorageService']['BlockStore'] = options.block_store

    if options.gc_interval :
        config['StorageService']['GarbageCollectionInterval'] = options.gc_interval

    # GO!
    LocalMain(config)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
