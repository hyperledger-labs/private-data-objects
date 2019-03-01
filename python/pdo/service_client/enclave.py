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

import logging
logger = logging.getLogger(__name__)

from pdo.service_client.generic import GenericServiceClient
from pdo.service_client.generic import MessageException
from pdo.service_client.storage import StorageServiceClient
from pdo.common.keys import EnclaveKeys

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class EnclaveException(Exception) :
    """
    A class to capture invocation exceptions
    """
    pass

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class EnclaveServiceClient(GenericServiceClient) :

    default_timeout = 20.0

    def __init__(self, url) :
        super().__init__(url)
        enclave_info = self.get_enclave_public_info()
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
    # encrypted_session_key -- base64 aes key encrypted with enclave's rsa key
    # encrypted_request -- base64 string encrypted with aes session key
    # -----------------------------------------------------------------
    def send_to_contract(self, encrypted_session_key, encrypted_request) :
        request = dict()
        request['encrypted_session_key'] = encrypted_session_key
        request['encrypted_request'] = encrypted_request

        try :
            url = '{0}/invoke'.format(self.ServiceURL)
            response = requests.post(url, json=request, timeout=self.default_timeout)
            response.raise_for_status()
            return response.text

        except (requests.HTTPError, requests.ConnectionError, requests.Timeout) as e :
            logger.warn('network error connecting to service (invoke); %s', str(e))
            raise MessageException(str(e)) from e

        except Exception as e :
            logger.warn('unknown exception (invoke); %s', str(e))
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
            response = requests.post(url, json=request, timeout=self.default_timeout)
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
            response = requests.get(url, timeout=self.default_timeout)
            response.raise_for_status()

            return response.json()

        except (requests.HTTPError, requests.ConnectionError, requests.Timeout) as e :
            logger.warn('network error connecting to service (get_enclave_public_info); %s', str(e))
            raise MessageException(str(e)) from e

        except Exception as e :
            logger.warn('unknown exception (get_enclave_public_info); %s', str(e))
            raise EnclaveException(str(e)) from e
