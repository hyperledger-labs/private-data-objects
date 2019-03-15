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
This file defines the VerifyApp class, a WSGI interface class for
handling requests to verify contract state encryption keys.
"""

import json

from http import HTTPStatus
from pdo.eservice.wsgi.common import ErrorResponse, UnpackRequest, CommonApp

import logging
logger = logging.getLogger(__name__)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class VerifyApp(CommonApp) :
    def __init__(self, enclave) :
        CommonApp.__init__(self, enclave)

    def __call__(self, environ, start_response) :
        request_identifier = environ.get('HTTP_X_REQUEST_IDENTIFIER','')
        session_identifier = environ.get('HTTP_X_SESSION_IDENTIFIER','')
        logger.debug('received verify request %s:%s', session_identifier, request_identifier)

        try :
            minfo = UnpackRequest(environ)
            contractid = minfo['contract_id']
            creatorid = minfo['creator_id']
            secrets = minfo['secrets']

            # verify the integrity of the secret list
            for secret in secrets :
                assert secret['pspk']
                assert secret['encrypted_secret']

        except KeyError as ke :
            logger.error('missing field in request (Verify): %s', ke)
            return ErrorResponse(start_response, 'missing field {0}'.format(ke))
        except Exception as e :
            logger.error("unknown exception unpacking request (Verify); %s", str(e))
            return ErrorResponse(start_response, "unknown exception while unpacking request")

        try :
            response = self.enclave.verify_secrets(contractid, creatorid, secrets)

        except Exception as e :
            logger.error('unknown exception processing request (Verify); %s', str(e))
            return ErrorResponse(start_response, 'uknown exception processing request')

        try :
            result = json.dumps(dict(response)).encode()
        except Exception as e :
            logger.error("unknown exception packing response (Verify); %s", str(e))
            return ErrorResponse(start_response, "unknown exception while packing response")

        status = "{0} {1}".format(HTTPStatus.OK.value, HTTPStatus.OK.name)
        headers = [
                   ('Content-Type', 'application/json'),
                   ('Content-Length', str(len(result)))
                   ]
        start_response(status, headers)
        return [result]
