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

from pdo.common.wsgi import ErrorResponse

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class ListBlocksApp(object) :
    def __init__(self, block_store) :
        self.block_store = block_store

    def __call__(self, environ, start_response) :
        try :
            block_ids = self.block_store.list_blocks(encoding='b64')
            result = json.dumps(block_ids).encode()

        except Exception as e :
            logger.exception('ListBlocksApp')
            return ErrorResponse(start_response, "unknown exception while processing list blocks request")

        status = "{0} {1}".format(HTTPStatus.OK.value, HTTPStatus.OK.name)
        headers = [
                   ('Content-Type', 'application/json'),
                   ('Content-Transfer-Encoding', 'utf-8'),
                   ('Content-Length', str(len(result)))
                   ]
        start_response(status, headers)
        return [result]
