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

from pdo.common.wsgi import ErrorResponse, UnpackMultipartRequest, IndexMultipartRequest

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class InitializeApp(object) :
    def __init__(self, enclave) :
        self.enclave = enclave

    def __call__(self, environ, start_response) :
        try :
            request = UnpackMultipartRequest(environ)
            request_index = IndexMultipartRequest(request)
            encrypted_session_key = request.parts[request_index['encrypted_session_key']].content
            encrypted_request = request.parts[request_index['encrypted_request']].content
        except KeyError as ke :
            logger.error('missing field in request: %s', ke)
            return ErrorResponse(start_response, 'missing field {0}'.format(ke))
        except Exception as e :
            logger.error("unknown exception unpacking request (Initialize); %s", str(e))
            return ErrorResponse(start_response, "unknown exception while unpacking request")

        try :
            result = self.enclave.initialize_contract_state(encrypted_session_key, encrypted_request)
        except Exception as e :
            logger.error('unknown exception processing request (Initialize); %s', str(e))
            return ErrorResponse(start_response, 'unknown exception processing request')

        status = "{0} {1}".format(HTTPStatus.OK.value, HTTPStatus.OK.name)
        headers = [
                   ('Content-Type', 'application/octet-stream'),
                   ('Content-Transfer-Encoding', 'utf-8'),
                   ('Content-Length', str(len(result)))
                   ]
        start_response(status, headers)
        return [result]
