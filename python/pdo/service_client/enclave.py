# Copyright 2018 Intel Corporation
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

import json
import requests
import base64
import time

import logging
logger = logging.getLogger(__name__)

from pdo.service_client.generic import GenericServiceClient
from pdo.service_client.generic import MessageException
from pdo.service_client.storage import StorageServiceClient
from pdo.common.keys import EnclaveKeys
import pdo.common.crypto as crypto

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class EnclaveException(Exception) :
    """
    A class to capture invocation exceptions
    """
    pass

class RetryException(Exception) :
    """
    A class for exceptions in the enclave service that
    could be handled through a retry
    """
    pass

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class EnclaveServiceClient(GenericServiceClient) :

    default_timeout = 20.0

    def __init__(self, url) :
        super().__init__(url)
        self.session = requests.Session()
        self.session.headers.update({'x-session-identifier' : self.Identifier})
        self.request_identifier = 0

        enclave_info = self.get_enclave_public_info()
        self.interpreter = enclave_info['interpreter']
        self.enclave_keys = EnclaveKeys(enclave_info['verifying_key'], enclave_info['encryption_key'])

        self.storage_service_url = enclave_info['storage_service_url']
        self.storage_service_client = StorageServiceClient(self.storage_service_url)
        self._attach_storage_service_(self.storage_service_client)

    @property
    def verifying_key(self) :
        self.enclave_keys.verifying_key

    @property
    def encryption_key(self) :
        self.enclave_keys.encryption_key

    @property
    def enclave_id(self) :
        return self.enclave_keys.identity

    # -------------------------------------------------------
    def _attach_storage_service_(self, storage_service) :
        self.storage_service_verifying_key = storage_service.verifying_key

        self.get_block = storage_service.get_block
        self.get_blocks = storage_service.get_blocks
        self.store_block = storage_service.store_block
        self.store_blocks = storage_service.store_blocks
        self.check_block = storage_service.check_block
        self.check_blocks = storage_service.check_blocks

    # -----------------------------------------------------------------
    # encrypted_session_key -- byte string containing aes key encrypted with enclave's rsa key
    # encrypted_request -- byte string request encrypted with aes session key
    # -----------------------------------------------------------------
    def send_to_contract(self, encrypted_session_key, encrypted_request, encoding='raw') :
        request_identifier = self.request_identifier
        self.request_identifier += 1
        try :
            url = '{0}/invoke'.format(self.ServiceURL)
            request_headers = {'x-request-identifier' : 'request{0}'.format(request_identifier)}
            content_headers = {}
            if encoding == 'base64' :
                encrypted_session_key = base64.b64encode(encrypted_session_key)
                encrypted_request = base64.b64encode(encrypted_request)
                content_headers['Content-Transfer-Encoding'] = 'base64'

            request = dict()
            request['encrypted_session_key'] = (None, encrypted_session_key, 'application/octet-stream', content_headers)
            request['encrypted_request'] = (None, encrypted_request, 'application/octet-stream', content_headers)

            response = self.session.post(url, files=request, headers=request_headers, timeout=self.default_timeout, stream=False)
            response.raise_for_status()

            encoding = response.headers.get('Content-Transfer-Encoding','')
            content = response.content

            if encoding == 'base64' :
                return base64.b64decode(content)

            return content

        except requests.Timeout as e :
            logger.warn('[%d] requests timeout (invoke)', request_identifier)
            raise MessageException(str(e)) from e

        except requests.ConnectionError as e :
            logger.warn('[%d] connection error (invoke); %s', request_identifier, e.strerror)
            raise MessageException(str(e)) from e

        except requests.HTTPError as e :
            logger.warn('[%d] network error connecting to service (invoke); %s', request_identifier, str(e))
            raise MessageException(str(e)) from e

        except Exception as e :
            logger.warn('[%d] unknown exception (invoke); %s', request_identifier, str(e))
            raise EnclaveException(str(e)) from e


    # -----------------------------------------------------------------
    # contract_id -- 16 character, hex encoded, sha256 hashed, registration transaction signature
    # creator_id -- base64 encoded, sha256 hashed, creator verifying key
    # secret_list -- array of dictionaries, dictionary defines values for pspk and encrypted_secret
    # -----------------------------------------------------------------
    def verify_secrets(self, contract_id, owner_id, secret_list) :
        request = dict()
        request['contract_id'] = contract_id
        request['creator_id'] = owner_id
        request['secrets'] = secret_list

        try :
            url = '{0}/verify'.format(self.ServiceURL)
            while True :
                response = self.session.post(url, json=request, timeout=self.default_timeout, stream=False)
                if response.status_code == 429 :
                    logger.info('prepare to resubmit the request')
                    sleeptime = min(1.0, float(response.headers.get('retry-after', 1.0)))
                    time.sleep(sleeptime)
                    continue

                response.raise_for_status()
                return response.json()

        except (requests.HTTPError, requests.ConnectionError, requests.Timeout) as e :
            logger.warn('network error connecting to service (verify_secrets); %s', str(e))
            raise MessageException(str(e)) from e

        except Exception as e :
            logger.warn('unknown exception (verify_secrets); %s', str(e))
            raise EnclaveException(str(e)) from e

    # -----------------------------------------------------------------
    def get_enclave_public_info(self) :
        try :
            url = '{0}/info'.format(self.ServiceURL)
            while True :
                response = self.session.get(url, timeout=self.default_timeout)
                if response.status_code == 429 :
                    logger.info('prepare to resubmit the request')
                    sleeptime = min(1.0, float(response.headers.get('retry-after', 1.0)))
                    time.sleep(sleeptime)
                    continue

                response.raise_for_status()
                return response.json()

        except (requests.HTTPError, requests.ConnectionError, requests.Timeout) as e :
            logger.warn('network error connecting to service (get_enclave_public_info); %s', str(e))
            raise MessageException(str(e)) from e

        except Exception as e :
            logger.warn('unknown exception (get_enclave_public_info); %s', str(e))
            raise EnclaveException(str(e)) from e
