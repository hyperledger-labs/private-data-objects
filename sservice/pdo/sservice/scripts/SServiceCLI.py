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

import signal

from pdo.common.block_store_manager import BlockStoreManager
from pdo.common.wsgi import AppWrapperMiddleware
from pdo.sservice.wsgi import *
from pdo.sservice.wsgi import wsgi_block_operation_map

import pdo.common.config as pconfig
import pdo.common.keys as keys
import pdo.common.logger as plogger

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
from twisted.web import http
from twisted.web.resource import Resource, NoResource
from twisted.web.server import Site
from twisted.python.threadpool import ThreadPool
from twisted.internet import reactor, defer, task
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.web.wsgi import WSGIResource

## ----------------------------------------------------------------
def ErrorResponse(request, error_code, msg) :
    """
    Generate a common error response for broken requests
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
def __shutdown__(*args) :
    logger.warn('shutdown request received')
    reactor.callLater(1, reactor.stop)

def StartStorageService(config, block_store, service_keys) :
    try :
        http_port = config['StorageService']['HttpPort']
        http_host = config['StorageService']['Host']
        worker_threads = config['StorageService'].get('WorkerThreads', 8)
        reactor_threads = config['StorageService'].get('ReactorThreads', 8)
    except KeyError as ke :
        logger.error('missing configuration for %s', str(ke))
        sys.exit(-1)

    logger.info('service started on port %s', http_port)

    thread_pool = ThreadPool(maxthreads=worker_threads)
    thread_pool.start()
    reactor.addSystemEventTrigger('before', 'shutdown', thread_pool.stop)

    block = Resource()
    for (wsgi_verb, wsgi_app) in wsgi_block_operation_map.items() :
        logger.info('add handler for %s', wsgi_verb)
        verb = wsgi_verb.encode('utf8')
        app = AppWrapperMiddleware(wsgi_app(config, block_store, service_keys))
        block.putChild(verb, WSGIResource(reactor, thread_pool, app))

    root = Resource()
    root.putChild(b'info', WSGIResource(reactor, thread_pool, AppWrapperMiddleware(InfoApp(config, service_keys))))
    root.putChild(b'block', block)

    site = Site(root, timeout=60)
    site.displayTracebacks = True

    reactor.suggestThreadPoolSize(reactor_threads)

    signal.signal(signal.SIGQUIT, __shutdown__)
    signal.signal(signal.SIGTERM, __shutdown__)

    endpoint = TCP4ServerEndpoint(reactor, http_port, backlog=32, interface=http_host)
    endpoint.listen(site)


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
        try :
            key_config = config.get('Key', {})
            key_file = key_config['FileName']
            key_path = key_config['SearchPath']
            service_keys = keys.ServiceKeys.read_from_file(key_file, search_path = key_path)
        except KeyError as ke :
            logger.error('missing configuration for Key.%s', str(ke))
            sys.exit(-1)
        except Exception as e :
            logger.error('unable to load transaction keys; %s', str(e))
            sys.exit(-1)

        try :
            service_config = config.get('StorageService', {})
            create = config.get('create', False)
            block_store_file = service_config['BlockStore']
            block_store = BlockStoreManager(block_store_file, create_block_store=create)

        except KeyError as ke :
            logger.error('missing configuration for StorageService.%s', str(ke))
            sys.exit(-1)
        except Exception as e :
            logger.error('unable to open the block store; %s', str(e))
            sys.exit(-1)

        try :
            service_config = config.get('StorageService', {})
            gcinterval = service_config['GarbageCollectionInterval']
            if gcinterval < 0 :
                gcinterval = 0            # gcinterval 0 means don't run the garbage collector

            if gcinterval > 0 :
                StartGarbageCollector(block_store, gcinterval)
            StartStorageService(config, block_store, service_keys)
        except Exception as e :
            logger.error('failed to start services; %s', str(e))
            sys.exit(-1)

    except Exception as e:
        logger.exception('failed to initialize the storage service; %s', e)
        sys.exit(-1)

    RunService(block_store)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

## -----------------------------------------------------------------
ContractHost = os.environ.get("PDO_HOSTNAME", "localhost")
ContractHome = os.environ.get("PDO_HOME") or os.path.realpath("/opt/pdo")
ContractEtc = os.path.join(ContractHome, "etc")
ContractKeys = os.path.join(ContractHome, "keys")
ContractLogs = os.path.join(ContractHome, "logs")
ContractData = os.path.join(ContractHome, "data")
LedgerURL = os.environ.get("PDO_LEDGER_URL", "http://127.0.0.1:6600/")
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

    # set up the storage service configuration
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
