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

import json
from cgi import FieldStorage
from http import HTTPStatus

import logging
logger = logging.getLogger(__name__)

## ----------------------------------------------------------------
def ErrorResponse(start_response, msg) :
    """Generate a common error response for broken requests
    """

    result = msg + '\n'
    result = result.encode('utf8')

    status = "{0} {1}".format(HTTPStatus.BAD_REQUEST.value, HTTPStatus.BAD_REQUEST.name)
    headers = [
               ('Content-Type', 'text/plain'),
               ('Content-Length', str(len(result)))
               ]

    start_response(status, headers)
    return [result]

## -----------------------------------------------------------------
def UnpackRequest(environ) :
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
def UnpackMultipart(environ):
    """
    """

    request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    request_encoding = environ.get('CONTENT_TYPE','')
    if not request_encoding.startswith('multipart/form-data') :
        msg = 'unknown message encoding, <{0}>'.format(request_encoding)
        raise Exception(msg)

    return FieldStorage(fp=environ['wsgi.input'], environ=environ, keep_blank_values=True)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class CommonApp(object) :
    request_identifier = 0

    ## -----------------------------------------------------------------
    def __init__(self, enclave) :
        self.enclave = enclave
        self.identifier = CommonApp.request_identifier

        CommonApp.request_identifier += 1
