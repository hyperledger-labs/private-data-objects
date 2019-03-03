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
import logging
import pdo.common.logger as plogger

logger = logging.getLogger(__name__)

from pdo.service_client.storage import StorageServiceClient

# -----------------------------------------------------------------
# -----------------------------------------------------------------
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--url', help='storage service url', required=True, type=str)
parser.add_argument('--loglevel', help='Set the logging level', default='INFO')
parser.add_argument('--logfile', help='Name of the log file', default='__screen__')
options = parser.parse_args()

# -----------------------------------------------------------------
# -----------------------------------------------------------------
plogger.setup_loggers({'LogLevel' : options.loglevel.upper(), 'LogFile' : options.logfile})

# -----------------------------------------------------------------
# -----------------------------------------------------------------
client = StorageServiceClient(options.url)

# -----------------------------------------------------------------
# Begin the tests
# -----------------------------------------------------------------

# -----------------------------------------------------------------
logger.info('attempt to put a single block to the service')
# -----------------------------------------------------------------
try :
    block_data = os.urandom(1000)
    block_id = client.put_block(block_data)
    assert block_id
except Exception as e :
    logger.error('put test failed; %s', str(e))
    sys.exit(-1)

# -----------------------------------------------------------------
logger.info('verify that the put succeeded')
# -----------------------------------------------------------------
try :
    verify_block_data = client.get_block(block_id)
    assert block_data == verify_block_data
except Exception as e :
    logger.error('verify put test failed; %s', str(e))
    sys.exit(-1)

# -----------------------------------------------------------------
logger.info('test bulk upload of blocks')
# -----------------------------------------------------------------
try :
    block_data = []
    block_data.append(os.urandom(10))
    block_data.append(os.urandom(10))
    block_data.append(os.urandom(10))
    block_ids = client.put_blocks(block_data)
    assert block_ids and len(block_ids) == 3
except Exception as e :
    logger.error('bulk upload test failed; %s', str(e))
    sys.exit(-1)

# -----------------------------------------------------------------
logger.info('verify that the upload succeeded')
# -----------------------------------------------------------------
try :
    for i in range(len(block_ids)) :
        verify_block_data = client.get_block(block_ids[i])
        assert block_data[i] == verify_block_data
except Exception as e :
    logger.error('failed to verify bulk upload; %s', str(e))
    sys.exit(-1)

# -----------------------------------------------------------------
logger.info('test bulk status')
# -----------------------------------------------------------------
try :
    status = client.check_status(block_ids)
    assert status and len(status) == 3
except Exception as e :
    logger.error('bulk status failed; %s', str(e))
    sys.exit(-1)

# -----------------------------------------------------------------
logger.info('make sure we get an error for a bad block id')
# -----------------------------------------------------------------
try :
    block_data = client.get_block('abcd')
except Exception as e:
    pass
else :
    logger.error('failed to catch bad request')
    sys.exit(-1)
