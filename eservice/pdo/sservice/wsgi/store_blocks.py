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

from itertools import islice
import json
from http import HTTPStatus

from pdo.common.wsgi import ErrorResponse, UnpackMultipartRequest

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class StoreBlocksApp(object) :
    ## -----------------------------------------------------------------
    def __init__(self, block_store) :
        self.block_store = block_store

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
            expiration = minfo['expiration']
        except Exception as e :
            logger.exception('StoreBlocksApp')
            return ErrorResponse(start_response, "unknown exception while unpacking block store request")

        try :
            # block_list will be an iterator for blocks in the request, this prevents
            # the need to make a copy of the data blocks
            block_list = self.block_data_iterator(request)
            raw_result = self.block_store.store_blocks(block_list, expiration=expiration, encoding='b64')
        except Exception as e :
            logger.exception('StoreBlocksApp')
            return ErrorResponse(start_response, "unknown exception while storing blocks")

        try :
            result = json.dumps(raw_result).encode('utf8')
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
