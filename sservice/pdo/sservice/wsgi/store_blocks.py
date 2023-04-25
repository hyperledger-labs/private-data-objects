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
This file defines the InvokeApp class, a WSGI interface class for
handling contract method invocation requests.
"""

import base64
import hashlib
from http import HTTPStatus
from itertools import islice
import json

from pdo.common.wsgi import ErrorResponse, UnpackMultipartRequest

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class StoreBlocksApp(object) :
    ## -----------------------------------------------------------------
    def __init__(self, config, block_store, service_keys) :
        self.block_store = block_store
        self.service_keys = service_keys
        self.max_duration = config['StorageService'].get('MaxDuration', 0)

    ## -----------------------------------------------------------------
    def block_data_iterator(self, request) :
        """create an iterator for the blocks in the request
        """
        for part in islice(request.parts, 1, None) :
            yield part.content

    ## -----------------------------------------------------------------
    def __call__(self, environ, start_response) :
        # get the block id from the URL path

        try :
            request = UnpackMultipartRequest(environ)
            if len(request.parts) < 1 :
                return ErrorResponse(start_response, 'missing block store operation')

            operation = request.parts[0]
            if operation.headers[b'Content-Type'] != b'application/json' :
                return ErrorResponse(start_response, 'missing block store operation')

            data = operation.text
            try:
                data = data.decode('utf-8')
            except AttributeError:
                pass

            minfo = json.loads(data)
            duration = minfo['duration']
        except Exception as e :
            logger.exception('StoreBlocksApp')
            return ErrorResponse(start_response, "unknown exception while unpacking block store request")

        if self.max_duration > 0 :
            duration = min(duration, self.max_duration)

        try :
            # block_list will be an iterator for blocks in the request, this prevents
            # the need to make a copy of the data blocks
            block_list = self.block_data_iterator(request)
            block_hashes = self.block_store.store_blocks(block_list, duration=duration, encoding='b64')
        except Exception as e :
            logger.exception('StoreBlocksApp')
            return ErrorResponse(start_response, "unknown exception while storing blocks")

        try :
            # going to just concatenate all hashes, safe since these are all fixed size
            signing_hash_accumulator = duration.to_bytes(32, byteorder='big', signed=False)
            signing_hash_accumulator += b''.join(block_hashes)

            signing_hash = hashlib.sha256(signing_hash_accumulator).digest()
            signature = self.service_keys.sign(signing_hash, encoding='b64')
        except Exception as e :
            logger.exception("unknown exception packing response (BlockStatus); %s", str(e))
            return ErrorResponse('signature generation failed')

        encoding_fn = lambda x : base64.urlsafe_b64encode(x).decode()

        result = dict()
        result['signature'] = signature
        result['block_ids'] = list(map(encoding_fn, block_hashes))
        result['duration'] = duration

        try :
            result = json.dumps(result).encode('utf8')
        except Exception as e :
            logger.exception('StoreBlocksApp')
            return ErrorResponse(start_response, "unknown exception while packing response")

        status = "{0} {1}".format(HTTPStatus.OK.value, HTTPStatus.OK.name)
        headers = [
                   ('Content-Type', 'application/json'),
                   ('Content-Transfer-Encoding', 'utf-8'),
                   ('Content-Length', str(len(result)))
                   ]
        start_response(status, headers)
        return [result]
