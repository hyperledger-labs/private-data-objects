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
import base64
import hashlib

import logging
import pdo.common.logger as plogger

logger = logging.getLogger(__name__)

import pdo.common.crypto as crypto
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
def decode_block_id(block_id) :
    return base64.urlsafe_b64decode(block_id)

def verify_store_signature(store_response, expiration, verifying_key) :
    block_hashes = map(decode_block_id, store_response['block_ids'])

    signing_hash_accumulator = expiration.to_bytes(32, byteorder='big', signed=False)
    signing_hash_accumulator += b''.join(block_hashes)
    signing_hash = hashlib.sha256(signing_hash_accumulator).digest()

    decoded_signature = base64.urlsafe_b64decode(store_response['signature'])

    vk = crypto.SIG_PublicKey(verifying_key)
    return vk.VerifySignature(signing_hash, decoded_signature)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
client = StorageServiceClient(options.url)

# -----------------------------------------------------------------
# Begin the tests
# -----------------------------------------------------------------
# -----------------------------------------------------------------
logger.info('attempt to put a single block to the service')
# -----------------------------------------------------------------
default_expiration = 30
try :
    block_data = os.urandom(1000)
    result = client.store_blocks([block_data], expiration=default_expiration)
    assert result

    assert verify_store_signature(result, default_expiration, client.verifying_key)

    block_ids = result['block_ids']
    assert block_ids and len(block_ids) == 1

    block_id = result['block_ids'][0]
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
    result = client.store_blocks(block_data, expiration=default_expiration)
    assert result

    assert verify_store_signature(result, default_expiration, client.verifying_key)

    block_ids = result['block_ids']
    logger.info('RESULT: %s', result)
    assert block_ids and len(block_ids) == 3

except Exception as e :
    logger.exception('bulk upload test failed; %s', str(e))
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
logger.info('verify that the upload succeeded using bulk get')
# -----------------------------------------------------------------
try :
    verify_block_data_list = client.get_blocks(block_ids)
    for i in range(len(block_ids)) :
        assert block_data[i] == verify_block_data_list[i]
except Exception as e :
    logger.error('failed to verify bulk upload; %s', str(e))
    sys.exit(-1)

# -----------------------------------------------------------------
logger.info('test bulk status')
# -----------------------------------------------------------------
try :
    status = client.check_blocks(block_ids)
    assert status and len(status) == 3
    for s in status :
        assert s['size'] == 10
        assert 0 < s['expiration'] and s['expiration'] <= 30

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

logger.info('all tests passed')
sys.exit(0)
