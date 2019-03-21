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
Enclave service.
"""

import cgi
import json

from requests_toolbelt.multipart.decoder import MultipartDecoder
from http import HTTPStatus

import logging
logger = logging.getLogger(__name__)

## ----------------------------------------------------------------
def ErrorResponse(start_response, msg, status=None) :
    """Generate a common error response for broken requests
    """

    logger.info('error response: %s', msg)

    result = msg + '\n'
    result = result.encode('utf8')

    if status is None :
        status = HTTPStatus.BAD_REQUEST

    status_msg = "{0} {1}".format(status.value, status.name)
    headers = [
               ('Content-Type', 'text/plain'),
               ('Content-Length', str(len(result)))
               ]

    start_response(status_msg, headers)
    return [result]

## -----------------------------------------------------------------
def UnpackJSONRequest(environ) :
    """Unpack a JSON request that has been received; this procedure
    is really about making sure that the bytes are in a string format
    that will work across python versions.
    """

    request_body_size = int(environ.get('CONTENT_LENGTH', 0))

    request_encoding = environ.get('CONTENT_TYPE','')
    if request_encoding != 'application/json' :
        msg = 'unknown message encoding, {0}'.format(request_encoding)
        raise Exception(msg)

    # Attempt to decode the data if it is not already a string
    request_body = environ['wsgi.input'].read(request_body_size)
    return json.loads(request_body)

## -----------------------------------------------------------------
def UnpackMultipartRequest(environ) :
    """Unpack a multipart request
    """

    request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    request_type = environ.get('CONTENT_TYPE','')
    if not request_type.startswith('multipart/form-data') :
        msg = 'unknown request type, <{0}>'.format(request_type)
        raise Exception(msg)

    request_body = environ['wsgi.input'].read(request_body_size)
    return MultipartDecoder(request_body, request_type)

## -----------------------------------------------------------------
def IndexMultipartRequest(request) :
    """Process the headers for the multipart request and create
    an index of the names that are found
    """
    index = {}
    for p in range(0, len(request.parts)) :
        value, headers = cgi.parse_header(request.parts[p].headers[b'Content-Disposition'].decode())
        name = headers.get('name')
        if name is None :
            logger.warn('missing name from multipart request')
        index[name] = p

    return index

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class AppWrapperMiddleware(object) :

    def __init__(self, wrapped_app) :
        self.wrapped_app = wrapped_app

    def __call__(self, environ, start_response) :
        """Wrap the call to the underlying application
        """

        request_identifier = environ.get('HTTP_X_REQUEST_IDENTIFIER','')
        session_identifier = environ.get('HTTP_X_SESSION_IDENTIFIER','')
        logger.debug('received info request %s:%s', session_identifier, request_identifier)

        return self.wrapped_app(environ, start_response)
