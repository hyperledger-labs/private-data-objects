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
This file defines the InfoApp class, a WSGI interface class for
handling requests for enclave service information.
"""

import json

from http import HTTPStatus
from pdo.eservice.wsgi.common import ErrorResponse, CommonApp

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class InfoApp(CommonApp) :
    def __init__(self, enclave, storage_url) :
        CommonApp.__init__(self, enclave)
        self.storage_url = storage_url

    def __call__(self, environ, start_response) :
        request_identifier = environ.get('HTTP_X_REQUEST_IDENTIFIER','')
        session_identifier = environ.get('HTTP_X_SESSION_IDENTIFIER','')
        logger.debug('received info request %s:%s', session_identifier, request_identifier)

        try :
            response = dict()
            response['verifying_key'] = self.enclave.verifying_key
            response['encryption_key'] = self.enclave.encryption_key
            response['enclave_id'] = self.enclave.enclave_id
            response['storage_service_url'] = self.storage_url

            result = json.dumps(response).encode()
        except Exception as e :
            logger.exception("info")
            return ErrorResponse(start_response, "exception; {0}".format(str(e)))

        status = "{0} {1}".format(HTTPStatus.OK.value, HTTPStatus.OK.name)
        headers = [
                   ('Content-Type', 'application/json'),
                   ('Content-Length', str(len(result)))
                   ]
        start_response(status, headers)
        return [result]
