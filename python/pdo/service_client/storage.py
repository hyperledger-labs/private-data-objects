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
class StorageServiceClient(object) :
    """A class to wrap calls to the storage service.
    """

    default_timeout = 1.0

    def __init__(self, url) :
        self.url_base = url
        self.service_info = self.get_service_info()

    @property
    def verifying_key(self) :
        return self.service_info['verifying_key']

    def get_service_info(self) :
        url = "{0}/info".format(self.url_base)
        response = requests.get(url, timeout=self.default_timeout)
        logger.info('get_service_info response code = %s', response.status_code)
        response.raise_for_status()
        return response.json()

    def list_blocks(self) :
        url = "{0}/block/list".format(self.url_base)
        response = requests.get(url, timeout=self.default_timeout)
        logger.info('get_block_list response code = %s', response.status_code)
        response.raise_for_status()
        return response.json()

    def get_block(self, block_id) :
        url = "{0}/block/{1}".format(self.url_base, block_id)
        response = requests.get(url, timeout=self.default_timeout)
        logger.info('get_block response code = %s', response.status_code)
        response.raise_for_status()
        return response.content

    def get_blocks(self, block_ids) :
        pass

    def store_block(self, block_data, expiration=60) :
        return self.store_blocks([block_data], expiration)

    def store_blocks(self, block_data_list, expiration=60) :
        request_data = dict()
        block_ids = []
        for i in range(len(block_data_list)) :
            block_hash = hashlib.sha256(block_data_list[i]).digest()
            block_id = base64.urlsafe_b64encode(block_hash).decode()
            block_ids.append(block_id)
            request_data[block_id] = (block_id, block_data_list[i], 'application/octet-stream')
        request_data['operation'] = json.dumps({'block_ids' : block_ids, 'expiration' : expiration})
        url = "{0}/block/store".format(self.url_base)
        response = requests.post(url, files=request_data, timeout=self.default_timeout)
        logger.info('store_blocks response code = %s', response.status_code)
        response.raise_for_status()
        return response.json()

    def check_blocks(self, block_ids) :
        url = "{0}/block/check".format(self.url_base)
        response = requests.post(url, json=block_ids, timeout=self.default_timeout)
        logger.info('check_blocks response code = %s', response.status_code)
        response.raise_for_status()
        return response.json()
