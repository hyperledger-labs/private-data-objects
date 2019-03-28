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

import os
import sys

import base64
import hashlib
import json
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder
from requests_toolbelt.multipart.decoder import MultipartDecoder

from pdo.service_client.generic import GenericServiceClient
from pdo.service_client.generic import MessageException

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class StorageException(Exception) :
    """A class to capture storage exceptions
    """
    pass

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class StorageServiceClient(GenericServiceClient) :
    """A class to wrap calls to the storage service.
    """

    default_timeout = 1.0

    # -----------------------------------------------------------------
    def __init__(self, url) :
        super().__init__(url)
        self.session = requests.Session()
        self.session.headers.update({'x-session-identifier' : self.Identifier})
        self.request_identifier = 0

        self.service_info = self.get_service_info()

    # -----------------------------------------------------------------
    @property
    def verifying_key(self) :
        return self.service_info['verifying_key']

    # -----------------------------------------------------------------
    def get_service_info(self) :
        """Retrieve information from the storage service, specifically this returns
        the ECDSA verifying key
        """
        request_identifier = self.request_identifier
        request_headers = {'x-request-identifier' : 'request{0}'.format(request_identifier)}

        url = "{0}/info".format(self.ServiceURL)
        try :
            response = self.session.get(url, headers=request_headers, timeout=self.default_timeout)
        except Exception as e :
            logger.warn('unknown exception (get_service_info); %s', str(e))
            raise StorageException(str(e)) from e

        response.raise_for_status()
        return response.json()

    # -----------------------------------------------------------------
    def list_blocks(self) :
        """Get a list of all blocks currently stored on the storage service; this is
        primarily a debugging function.
        """
        request_identifier = self.request_identifier
        request_headers = {'x-request-identifier' : 'request{0}'.format(request_identifier)}

        url = "{0}/block/list".format(self.ServiceURL)
        try :
            response = self.session.get(url, timeout=self.default_timeout)
        except Exception as e :
            logger.warn('unknown exception (list_blocks); %s', str(e))
            raise StorageException(str(e)) from e

        response.raise_for_status()
        return response.json()

    # -----------------------------------------------------------------
    def get_block(self, block_id) :
        """Get a single block from the storage service using the get block
        interface, block_id should be base64 encoded
        """
        request_identifier = self.request_identifier
        request_headers = {'x-request-identifier' : 'request{0}'.format(request_identifier)}

        # we need to make sure this function uses urlsafe b64 encoding
        block_id = block_id.replace('+','-')
        block_id = block_id.replace('/','_')

        url = "{0}/block/get/{1}".format(self.ServiceURL, block_id)
        try :
            response = self.session.get(url, timeout=self.default_timeout)
        except Exception as e :
            logger.warn('unknown exception (get_block); %s', str(e))
            raise StorageException(str(e)) from e

        response.raise_for_status()
        return response.content

    # -----------------------------------------------------------------
    def get_blocks(self, block_ids) :
        """Get a list of blocks from the storage service using the get blocks
        interface, block ids should be base64 encoded

        :param block_ids: list of base64 encoded strings
        :returns list of strings: list of byte strings containing block data
        """
        request_identifier = self.request_identifier
        request_headers = {'x-request-identifier' : 'request{0}'.format(request_identifier)}

        url = "{0}/block/gets".format(self.ServiceURL)
        try :
            response = self.session.post(url, json=block_ids, timeout=self.default_timeout)
        except Exception as e :
            logger.warn('unknown exception (get_blocks); %s', str(e))
            raise StorageException(str(e)) from e

        response.raise_for_status()

        try :
            # decode the response, note that we put the multipart encoding into a
            # customer header because urllib3 doesn't seem to like requests.toolbelt's
            # multipart encoding
            mp_decoder = MultipartDecoder(response.content, response.headers['x-content-type'])

            block_data_list = []
            for part in mp_decoder.parts :
                block_data_list.append(part.content)

            return block_data_list
        except Exception as e :
            logger.warn('unknown exception (get_blocks); %s', str(e))
            raise StorageException(str(e)) from e

    # -----------------------------------------------------------------
    def store_block(self, block_data, expiration=60) :
        return self.store_blocks([block_data], expiration)

    # -----------------------------------------------------------------
    def store_blocks(self, block_data_list, expiration=60) :
        """Store a list of blocks on the storage server

        :param block_data_list: list of blocks represented as byte strings (iterator)
        :param expiration: number of seconds to request storage
        :returns dictionary: decoded result of the request
        """
        request_identifier = self.request_identifier
        request_headers = {'x-request-identifier' : 'request{0}'.format(request_identifier)}

        url = "{0}/block/store".format(self.ServiceURL)

        try :
            request_data = dict()
            request_data['operation'] = (None, json.dumps({'expiration' : expiration}), 'application/json')
            count = 0                     # just needed to uniquify the keys
            for block_data in block_data_list :
                request_data['block{0}'.format(count)] = (None, block_data, 'application/octet-stream')
                count += 1

            mp_encoder = MultipartEncoder(request_data)
            request_headers['content-type'] = mp_encoder.content_type
        except Exception as e :
            logger.warn('unknown exception (store_blocks); %s', str(e))
            raise StorageException(str(e)) from e
        try :
            response = self.session.post(url, data=mp_encoder.to_string(), headers=request_headers, timeout=self.default_timeout)
        except Exception as e :
            logger.warn('unknown exception (store_blocks); %s', str(e))
            raise StorageException(str(e)) from e

        response.raise_for_status()
        return response.json()

    # -----------------------------------------------------------------
    def check_block(self, block_id) :
        return self.check_blocks([block_id])

    # -----------------------------------------------------------------
    def check_blocks(self, block_ids) :
        """Check the status of blocks on the storage service
        :param block_ids: list of base64 encoded block ids
        :returns dictionary: decoded result of the request
        """

        request_identifier = self.request_identifier
        request_headers = {'x-request-identifier' : 'request{0}'.format(request_identifier)}

        url = "{0}/block/check".format(self.ServiceURL)
        try :
            response = self.session.post(url, json=block_ids, timeout=self.default_timeout)
        except Exception as e :
            logger.warn('unknown exception (check_blocks); %s', str(e))
            raise StorageException(str(e)) from e

        response.raise_for_status()
        return response.json()
