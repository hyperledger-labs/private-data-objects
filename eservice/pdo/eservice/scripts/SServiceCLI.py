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
import lmdb
import struct
import time

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
class BlockMetadata(object) :
    """Class to capture metadata stored with a block
    """

    minimum_expiration_time = 60

    @classmethod
    def unpack(cls, value) :
        metadata = struct.unpack('LLLL', value)

        obj = cls()
        obj.block_size = metadata[0]
        obj.create_time = metadata[1]
        obj.expiration_time = metadata[2]
        obj.mark = metadata[3]

        return obj

    def __init__(self) :
        self.block_size = 0
        self.create_time = 0
        self.expiration_time = 0
        self.mark = 0

    def pack(self) :
        value = struct.pack('LLLL', self.block_size, self.create_time, self.expiration_time, self.mark)
        return value

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class CommonResource(Resource) :

    ## -----------------------------------------------------------------
    def __init__(self, service_keys, block_store_env) :
        Resource.__init__(self)
        self.service_keys = service_keys
        self.block_store_env = block_store_env

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
class BlockList(CommonResource) :
    isLeaf = True

    ## -----------------------------------------------------------------
    def __init__(self, service_keys, block_store_env) :
        CommonResource.__init__(self, service_keys, block_store_env)

    ## -----------------------------------------------------------------
    def _handle_request_(self, request) :
        try :
            mdb = self.block_store_env.open_db(b'meta_data')

            block_ids = []
            with self.block_store_env.begin() as txn :
                cursor = txn.cursor(db=mdb)
                for key, value in cursor :
                    block_ids.append(base64.urlsafe_b64encode(key).decode())

            result = json.dumps(block_ids).encode()

        except Exception as e :
            logger.error("unknown exception (BlockList); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while processing list blocks request")

        request.setHeader('content-type', 'application/json')
        request.write(result)

        return request

    ## -----------------------------------------------------------------
    def render_GET(self, request) :
        return self._defer_request_(self._handle_request_, request)


## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class BlockData(CommonResource) :

    ## -----------------------------------------------------------------
    def __init__(self, service_keys, block_store_env, block_hash) :
        CommonResource.__init__(self, service_keys, block_store_env)
        self.block_hash = block_hash

    ## -----------------------------------------------------------------
    def _handle_get_request_(self, request) :
        try :
            try :
                block_hash = base64.urlsafe_b64decode(self.block_hash)
            except :
                return ErrorResponse(request, http.BAD_REQUEST, "invalid block hash; {0}".format(self.block_hash))

            with self.block_store_env.begin() as txn :
                bdb = self.block_store_env.open_db(b'block_data')
                block_data = txn.get(block_hash, db=bdb)
                if not block_data :
                    return ErrorResponse(request, http.NOT_FOUND, "no such block; {0}".format(self.block_hash))

            request.setResponseCode(http.OK)
            request.setHeader('content-type', 'application/octet-stream')
            request.write(block_data)
            return request

        except Exception as e :
            logger.error("unknown exception (BlockGet); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST,
                                 "unknown exception while processing get block request; {0}".format(self.block_hash))

    ## -----------------------------------------------------------------
    def _handle_put_request_(self, request) :
        try :
            try :
                requested_block_hash = base64.urlsafe_b64decode(self.block_hash)
            except :
                return ErrorResponse(request, http.BAD_REQUEST, "invalid block hash; {0}".format(self.block_hash))

            block_data = request.content.getvalue()
            block_hash = hashlib.sha256(block_data).digest()
            if requested_block_hash != block_hash :
                return ErrorResponse(request, http.BAD_REQUEST, "mismatch block hash; {0}".format(self.block_hash))

            current_time = int(time.time())
            expiration_time = current_time + BlockMetadata.minimum_expiration_time

            # note that these must be outside of the transaction
            mdb = self.block_store_env.open_db(b'meta_data')
            bdb = self.block_store_env.open_db(b'block_data')

            with self.block_store_env.begin(write=True) as txn :
                # if the metadata (and implicitly the data) already exists then just
                # update the expiration time if it is older than the computed expiration
                raw_metadata = txn.get(block_hash, db=mdb)
                if raw_metadata :
                    metadata = BlockMetadata.unpack(raw_metadata)
                    if expiration_time > metadata.expiration_time :
                        metadata.expiration_time = expiration_time
                        if not txn.put(block_hash, metadata.pack(), db=mdb, overwrite=True) :
                            return Error(request, http.BAD_REQUEST, "failed to save updated metadata")
                else :
                    metadata = BlockMetadata()
                    metadata.block_size = len(block_data)
                    metadata.create_time = current_time
                    metadata.expiration_time = expiration_time
                    metadata.mark = 0
                    if not txn.put(block_hash, metadata.pack(), db=mdb) :
                        return Error(request, http.BAD_REQUEST, "failed to save metadata")

                    if not txn.put(block_hash, block_data, db=bdb) :
                        return ErrorResponse(request, http.BAD_REQUEST, "failed to save block data")

            request.setResponseCode(http.OK)
            request.write(b"SUCCESS\n")
            return request

        except Exception as e :
            logger.error("unknown exception (BlockPut); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST,
                                 "unknown exception while processing put block request; {0}".format(self.block_hash))

    ## -----------------------------------------------------------------
    def _handle_head_request_(self, request) :
        try :
            try :
                block_hash = base64.urlsafe_b64decode(self.block_hash)
            except :
                return ErrorResponse(request, http.BAD_REQUEST, "invalid block hash; {0}".format(self.block_hash))

            mdb = self.block_store_env.open_db(b'meta_data')

            block_size = -1
            with self.block_store_env.begin() as txn :
                raw_metadata = txn.get(block_hash, db=mdb)
                if raw_metadata :
                    metadata = BlockMetadata.unpack(raw_metadata)
                    block_size = metadata.block_size

            if block_size < 0 :
                request.setResponseCode(http.NOT_FOUND)
                request.setHeader('content-length', str(0))
                request.write(b"")
            else :
                request.setResponseCode(http.FOUND)
                request.setHeader('content-length', str(block_size))
                request.write(b"")

            return request

        except Exception as e :
            logger.error("unknown exception (BlockHead); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST,
                                 "unknown exception while processing block head request; {0}".format(self.block_hash))

    ## -----------------------------------------------------------------
    def render_GET(self, request) :
        return self._defer_request_(self._handle_get_request_, request)

    ## -----------------------------------------------------------------
    def render_PUT(self, request) :
        return self._defer_request_(self._handle_put_request_, request)

    ## -----------------------------------------------------------------
    def render_HEAD(self, request) :
        return self._defer_request_(self._handle_head_request_, request)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class BlockStatus(CommonResource) :
    isLeaf = True

    ## -----------------------------------------------------------------
    def __init__(self, service_keys, block_store_env) :
        CommonResource.__init__(self, service_keys, block_store_env)

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
            logger.error("unknown exception unpacking request (BlockStatus); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while unpacking block status request")

        try :
            current_time = int(time.time())
            mdb = self.block_store_env.open_db(b'meta_data')

            block_status_list = []
            with self.block_store_env.begin() as txn :

                for block_id in block_ids :
                    try :
                        block_hash = base64.urlsafe_b64decode(block_id)
                    except :
                        return ErrorResponse(request, http.BAD_REQUEST, "invalid block hash; {0}".format(block_id))

                    block_status = { 'block_id' : block_id, 'size' : 0, 'expiration' : 0 }

                    raw_metadata = txn.get(block_hash, db=mdb)
                    if raw_metadata :
                        metadata = BlockMetadata.unpack(raw_metadata)
                        block_status['size'] = metadata.block_size
                        block_status['expiration'] = metadata.expiration_time - current_time
                        if block_status['expiration'] < 0 :
                            block_status['expiration'] = 0

                    block_status_list.append(block_status)

        except Exception as e :
            logger.error("unknown exception computing status (BlockStatus); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while computing block status")

        try :
            result = json.dumps(block_status_list).encode()
        except Exception as e :
            logger.error("unknown exception packing response (BlockStatus); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while packing response")

        request.setHeader('content-type', 'application/json')
        request.write(result)
        return request

    ## -----------------------------------------------------------------
    def render_POST(self, request) :
        return self._defer_request_(self._handle_request_, request)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class BlockStore(CommonResource) :

    ## -----------------------------------------------------------------
    def __init__(self, service_keys, block_store_env) :
        CommonResource.__init__(self, service_keys, block_store_env)

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

            signing_hash_accumulator = expiration.to_bytes(32, byteorder='big', signed=False)

        except Exception as e :
            logger.error("unknown exception unpacking request (BlockStore); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while unpacking block store request")

        try :
            # expiration must be a positive number and less than one hour
            if expiration <= 0 or expiration > 60*60 :
                return ErrorResponse(request, http.BAD_REQUEST, "invalid expiration")

            current_time = int(time.time())
            expiration_time = current_time + expiration

            mdb = self.block_store_env.open_db(b'meta_data')
            bdb = self.block_store_env.open_db(b'block_data')

            # this might keep the database locked for too long for a write transaction
            # might want to flip the order, one transaction per update
            with self.block_store_env.begin(write=True) as txn :
                metadata = BlockMetadata()

                for block_id in block_ids :
                    block_id = block_id.encode()
                    try :
                        requested_block_hash = base64.urlsafe_b64decode(block_id)
                    except :
                        return ErrorResponse(request, http.BAD_REQUEST, "invalid block hash; {0}".format(block_id))

                    try :
                        block_data = request.args[block_id][0]
                    except :
                        return ErrorResponse(request, http.BAD_REQUEST, "missing block data; {0}".format(block_id))

                    block_hash = hashlib.sha256(block_data).digest()
                    if requested_block_hash != block_hash :
                        return ErrorResponse(request, http.BAD_REQUEST, "block hash mismatch; {0}".format(block_id))

                    metadata.block_size = len(block_data)
                    metadata.create_time = current_time
                    metadata.expiration_time = expiration_time
                    metadata.mark = 0

                    if not txn.put(block_hash, metadata.pack(), db=mdb) :
                        return Error(request, http.BAD_REQUEST, "failed to save metadata")

                    if not txn.put(block_hash, block_data, db=bdb) :
                        return ErrorResponse(request, http.BAD_REQUEST, "failed to save block data")

                    signing_hash_accumulator += block_hash

        except Exception as e :
            logger.error("unknown exception (BlockStore); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while storing blocks")

        try :
            signing_hash = hashlib.sha256(signing_hash_accumulator).digest()
            signature = self.service_keys.sign(signing_hash, encoding='b64')
            result = json.dumps({'signature' : signature}).encode('utf8')

        except Exception as e :
            logger.error("unknown exception packing response (BlockStatus); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while packing response")

        request.setHeader('content-type', 'application/json')
        request.write(result)
        return request

    ## -----------------------------------------------------------------
    def render_POST(self, request) :
        return self._defer_request_(self._handle_request_, request)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class BlockRoot(Resource) :

    ## -----------------------------------------------------------------
    def __init__(self, service_keys, block_store_env) :
        Resource.__init__(self)
        self.service_keys = service_keys
        self.block_store_env = block_store_env

    ## -----------------------------------------------------------------
    def getChild(self, name, request) :
        if name == b'list' :
            return BlockList(self.service_keys, self.block_store_env)
        elif name == b'status' :
            return BlockStatus(self.service_keys, self.block_store_env)
        elif name == b'store' :
            return BlockStore(self.service_keys, self.block_store_env)
        elif name :
            return BlockData(self.service_keys, self.block_store_env, name)
        else :
            return NoResource()

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class Info(CommonResource) :
    isLeaf = True

    ## -----------------------------------------------------------------
    def __init__(self, service_keys, block_store_env) :
        CommonResource.__init__(self, service_keys, block_store_env)

    ## -----------------------------------------------------------------
    def _handle_request_(self, request) :

        try :
            response = dict()
            response['verifying_key'] = self.service_keys.verifying_key
            result = json.dumps(response).encode()

        except Exception as e :
            logger.error("unknown exception (Info); %s", str(e))
            return ErrorResponse(request, http.BAD_REQUEST, "unknown exception while processing info request")

        request.setHeader('content-type', 'application/json')
        request.write(result)

        return request

    ## -----------------------------------------------------------------
    def render_GET(self, request) :
        return self._defer_request_(self._handle_request_, request)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class Shutdown(Resource) :
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
    def __init__(self, service_keys, block_store_env) :
        Resource.__init__(self)
        self.service_keys = service_keys
        self.block_store_env = block_store_env

    ## -----------------------------------------------------------------
    def getChild(self, name, request) :
        if name == b'block' :
            return BlockRoot(self.service_keys, self.block_store_env)
        elif name == b'info' :
            return Info(self.service_keys, self.block_store_env)
        elif name == b'shutdown' :
            return Shutdown()
        else :
            return NoResource()

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
def GarbageCollector(block_store_env) :
    logger.debug('run the garbage collector')
    try :
        mdb = block_store_env.open_db(b'meta_data')
        bdb = block_store_env.open_db(b'block_data')

        current_time = int(time.time())

        count = 0
        with block_store_env.begin() as txn :
            cursor = txn.cursor(db=mdb)
            for key, value in cursor :
                metadata = BlockMetadata.unpack(value)
                if metadata.expiration_time < current_time :
                    logger.debug('garbage collect block %s',base64.urlsafe_b64encode(key).decode())
                    count += 1
                    with block_store_env.begin(write=True) as dtxn :
                        assert dtxn.delete(key, db=bdb)
                        assert dtxn.delete(key, db=mdb)

        logger.info('garbage collector deleted %d blocks', count)
    except Exception as e :
        logger.error('garbage collection failed; %s', str(e))
        return

def StartGarbageCollector(block_store_env, gcinterval) :
    loop = task.LoopingCall(GarbageCollector, block_store_env)
    loopDeferred = loop.start(10.0)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
def StartStorageService(http_host, http_port, service_keys, block_store_env) :
    logger.info('service started on port %s', http_port)

    root = ContractStorageServer(service_keys, block_store_env)
    site = Site(root)

    threadpool = reactor.getThreadPool()
    threadpool.start()
    threadpool.adjustPoolsize(8, 100) # Min & Max number of request to service at a time
    logger.info('# of workers: %d', threadpool.workers)

    reactor.listenTCP(http_port, site, interface=http_host)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
def RunService(block_store_env) :

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
    block_store_env.sync()
    block_store_env.close()

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

            map_size = 1024 * 1024 * 1024
            create = config.get('create', False)
            block_store = service_config['BlockStore']
            block_store_env = lmdb.open(block_store, create=create, max_dbs=2, subdir=False, sync=False, map_size=map_size)

        except KeyError as ke :
            logger.error('missing configuration for StorageService.%s', str(ke))
            sys.exit(-1)
        except Exception as e :
            logger.error('unable to open the block store; %s', str(e))
            sys.exit(-1)

        try :
            StartGarbageCollector(block_store_env, gcinterval)
            StartStorageService(http_host, http_port, service_keys, block_store_env)
        except Exception as e :
            logger.error('failed to start services; %s', str(e))
            sys.exit(-1)

    except Error as e:
        logger.exception('failed to initialize the storage service; %s', e)
        sys.exit(-1)

    RunService(block_store_env)

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
            'HttpPort' : 7101,
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
