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
import pdo.common.block_store_manager as pblocks
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

def verify_store_signature(store_response, duration, verifying_key) :
    block_hashes = map(decode_block_id, store_response['block_ids'])

    signing_hash_accumulator = duration.to_bytes(32, byteorder='big', signed=False)
    signing_hash_accumulator += b''.join(block_hashes)
    signing_hash = hashlib.sha256(signing_hash_accumulator).digest()

    decoded_signature = base64.urlsafe_b64decode(store_response['signature'])

    vk = crypto.SIG_PublicKey(verifying_key)
    # VerifySignature returns 1 for a valid sig, 0 for an invalid sig and -1 on error
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
default_duration = pblocks.BlockMetadata.minimum_duration_time
try :
    block_data = os.urandom(1000)
    result = client.store_blocks([block_data], duration=default_duration)

    r = verify_store_signature(result, default_duration, client.verifying_key)
    if r < 0 :
        raise RuntimeError("unknown error occured during signature verification; {}".format(r))
    if r == 0 :
        raise ValueError("storage signature verification failed")

    block_ids = result.get('block_ids')
    if block_ids is None or type(block_ids) != list :
        raise RuntimeError('invalid response from block store')

    if len(block_ids) != 1:
        raise ValueError("too many blocks stored, expected 1 got {}".format(len(block_ids)))

    block_id = result['block_ids'][0]

except Exception as e :
    logger.error('put test failed; %s', str(e))
    sys.exit(-1)

# -----------------------------------------------------------------
logger.info('verify that the put succeeded')
# -----------------------------------------------------------------
try :
    verify_block_data = client.get_block(block_id)
    if block_data != verify_block_data:
        raise ValueError("retrieved block data different than expected")
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
    result = client.store_blocks(block_data, duration=default_duration)
    logger.info('RESULT: %s', result)

    r = verify_store_signature(result, default_duration, client.verifying_key)
    if r < 0 :
        raise RuntimeError("unknown error occured during signature verification; {}".format(r))
    if r == 0 :
        raise ValueError("storage signature verification failed")

    block_ids = result.get('block_ids')
    if block_ids is None or type(block_ids) != list :
        raise RuntimeError('invalid response from block store')

    if len(block_ids) != 3:
        raise ValueError("too many blocks stored, expected 3 got {}".format(len(block_ids)))

except Exception as e :
    logger.error('bulk upload test failed; %s', str(e))
    sys.exit(-1)

# -----------------------------------------------------------------
logger.info('verify that the upload succeeded')
# -----------------------------------------------------------------
try :
    for i in range(len(block_ids)) :
        verify_block_data = client.get_block(block_ids[i])
        if block_data[i] != verify_block_data:
            raise ValueError("retrieved block data different than expected: index {}".format(i))
except Exception as e :
    logger.error('failed to verify bulk upload; %s', str(e))
    sys.exit(-1)

# -----------------------------------------------------------------
logger.info('verify that the upload succeeded using bulk get')
# -----------------------------------------------------------------
try :
    verify_block_data_list = client.get_blocks(block_ids)
    for i in range(len(block_ids)) :
        if block_data[i] != verify_block_data_list[i]:
            raise ValueError("retrieved block data different than expected in list: index {}".format(i))
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
        if s['size'] != 10:
            raise ValueError("status size not 10: {}".format(s['size']))
        if 0 >= s['duration'] and s['duration'] > default_duration:
            raise ValueError("block status duration not within range: {}".format(s['duration']))

except Exception as e :
    logger.exception('bulk status failed; %s', str(e))
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
