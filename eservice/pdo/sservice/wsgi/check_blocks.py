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
import json

from pdo.common.wsgi import ErrorResponse, UnpackJSONRequest

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class CheckBlocksApp(object) :
    def __init__(self, block_store) :
        self.block_store = block_store

    def __call__(self, environ, start_response) :
        try :
            block_ids = UnpackJSONRequest(environ)

        except Exception as e :
            logger.exception('CheckBlocksApp')
            return ErrorResponse(start_response, "unknown exception while unpacking block status request")

        try :
            block_status_list = self.block_store.check_blocks(block_ids, encoding='b64')

        except Exception as e :
            logger.exception('CheckBlocksApp')
            return ErrorResponse(start_response, "unknown exception while computing block status")

        try :
            result = json.dumps(block_status_list).encode()
        except Exception as e :
            logger.exception('CheckBlocksApp')
            return ErrorResponse(start_response, "unknown exception while packing response")

        status = "{0} {1}".format(HTTPStatus.OK.value, HTTPStatus.OK.name)
        headers = [
                   ('Content-Type', 'application/json'),
                   ('Content-Transfer-Encoding', 'utf-8'),
                   ('Content-Length', str(len(result)))
                   ]
        start_response(status, headers)
        return [result]
