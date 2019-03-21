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

from http import HTTPStatus

from requests_toolbelt.multipart.encoder import MultipartEncoder

from pdo.common.wsgi import ErrorResponse, UnpackJSONRequest

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class GetBlockApp(object) :
    def __init__(self, block_store) :
        self.block_store = block_store

    def __call__(self, environ, start_response) :
        try :
            # get the block id from the URL path
            block_id = environ['PATH_INFO'][1:]               # skip the '/'
            if block_id is None :
                return ErrorResponse(start_response, "request missing block id")
        except Exception as e :
            logger.exception('get block')
            return ErrorResponse(start_response, 'unknown exception while unpacking the request')

        try :
            block_data = self.block_store.get_block(block_id, encoding='b64')
            if block_data is None :
                msg = "unknown block; {0}".format(block_id)
                return ErrorResponse(start_response, msg, status=HTTPStatus.NOT_FOUND)

        except Exception as e :
            logger.exception('get block')
            msg = "unknown exception while processing get block request; {0}".format(block_id)
            return ErrorResponse(start_response, msg)

        status = "{0} {1}".format(HTTPStatus.OK.value, HTTPStatus.OK.name)
        headers = [
                   ('Content-Type', 'application/octet-stream'),
                   ('Content-Transfer-Encoding', 'utf-8'),
                   ('Content-Length', str(len(block_data)))
                   ]
        start_response(status, headers)
        return [block_data]

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class GetBlocksApp(object) :
    def __init__(self, block_store) :
        self.block_store = block_store

    def __call__(self, environ, start_response) :
        try :
            block_ids = UnpackJSONRequest(environ)
        except Exception as e :
            logger.exception('get blocks')
            return ErrorResponse(start_response, 'unknown exception while unpacking get blocks request')
        try :
            response = dict()
            for block_id in block_ids :
                block_data = self.block_store.get_block(block_id, encoding='b64')
                if block_data is None :
                    msg = "unknown block; {0}".format(block_id)
                    return ErrorResponse(start_response, msg, status=HttpStatus.NOT_FOUND)
                response[block_id] = (None, block_data, 'application/octet-stream')

        except Exception as e :
            logger.exception('get blocks')
            return ErrorResponse(start_response, "unknown exception while processing get blocks request")

        try :
            encoder = MultipartEncoder(response)
        except Exception as e :
            logger.exception('get blocks')
            return ErrorResponse(start_response, 'unknown exception while packget get blocks response')

        status = "{0} {1}".format(HTTPStatus.OK.value, HTTPStatus.OK.name)
        headers = [
                   ('content-type', 'application/octet-stream'),
                   ('x-content-type', encoder.content_type),
                   ('content-transfer-encoding', 'utf-8'),
                   ('content-length', str(encoder.len))
                   ]
        start_response(status, headers)
        return [encoder.to_string()]
