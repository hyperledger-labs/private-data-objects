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

from pdo.eservice.wsgi.common import ErrorResponse, UnpackMultipart, CommonApp
from pdo.common.crypto import string_to_byte_array

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class InvokeApp(CommonApp) :
    def __init__(self, enclave) :
        CommonApp.__init__(self, enclave)

    def __call__(self, environ, start_response) :
        request_identifier = environ.get('HTTP_X_REQUEST_IDENTIFIER','')
        session_identifier = environ.get('HTTP_X_SESSION_IDENTIFIER','')
        logger.debug('received invoke request %s:%s', session_identifier, request_identifier)

        try :
            form = UnpackMultipart(environ)
            encrypted_session_key = form.getvalue('encrypted_session_key')
            encrypted_request = form.getvalue('encrypted_request')
        except KeyError as ke :
            logger.error('missing field in request: %s', ke)
            return ErrorResponse(start_response, 'missing field {0}'.format(ke))
        except Exception as e :
            logger.error("unknown exception unpacking request (Invoke); %s", str(e))
            return ErrorResponse(start_response, "unknown exception while unpacking request")

        try :
            result = self.enclave.send_to_contract_encoded(encrypted_session_key, encrypted_request)
            result = result.encode()
        except Exception as e :
            logger.error('unknown exception processing request (Invoke); %s', str(e))
            return ErrorResponse(start_response, 'unknown exception processing request')

        status = "{0} {1}".format(HTTPStatus.OK.value, HTTPStatus.OK.name)
        headers = [
                   ('Content-Type', 'application/octet-stream'),
                   ('Content-Transfer-Encoding', 'base64'),
                   ('Content-Length', str(len(result)))
                   ]
        start_response(status, headers)
        return [result]
