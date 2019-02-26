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
    """
    A class to capture storage exceptions
    """
    pass

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class StorageServiceClient(object) :
    def __init__(self, url) :
        self.url_base = url
        self.service_info = self.get_service_info()

    @property
    def verifying_key(self) :
        self.service_info['verifying_key']

    def get_service_info(self) :
        url = "{0}/info".format(self.url_base)
        response = requests.get(url)
        logger.info('get_service_info response code = %s', response.status_code)
        response.raise_for_status()
        return response.json()

    def get_block_list(self) :
        url = "{0}/block/list".format(self.url_base)
        response = requests.get(url)
        logger.info('get_block_list response code = %s', response.status_code)
        response.raise_for_status()
        return response.json()

    def get_block(self, block_id) :
        url = "{0}/block/{1}".format(self.url_base, block_id)
        response = requests.get(url)
        logger.info('get_block response code = %s', response.status_code)
        response.raise_for_status()
        return response.content

    def put_block(self, block_data) :
        block_hash = hashlib.sha256(block_data).digest()
        block_id = base64.urlsafe_b64encode(block_hash).decode()
        url = "{0}/block/{1}".format(self.url_base, block_id)
        response = requests.put(url, data=block_data)
        logger.info('put_block response code = %s', response.status_code)
        response.raise_for_status()
        return block_id

    def put_blocks(self, block_data_list) :
        request_data = dict()
        block_ids = []
        for i in range(len(block_data_list)) :
            block_hash = hashlib.sha256(block_data_list[i]).digest()
            block_id = base64.urlsafe_b64encode(block_hash).decode()
            block_ids.append(block_id)
            request_data[block_id] = (block_id, block_data_list[i], 'application/octet-stream')
        request_data['operation'] = json.dumps({'block_ids' : block_ids, 'interval' : 0})
        url = "{0}/block/store".format(self.url_base)
        response = requests.post(url, files=request_data)
        logger.info('put_blocks response code = %s', response.status_code)
        response.raise_for_status()
        return block_ids

    def check_status(self, block_ids) :
        url = "{0}/block/status".format(self.url_base)
        response = requests.post(url, json=block_ids)
        logger.info('put_blocks response code = %s', response.status_code)
        response.raise_for_status()
        return response.json()
