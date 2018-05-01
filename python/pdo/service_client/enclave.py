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

import logging
logger = logging.getLogger(__name__)

from pdo.service_client.generic import GenericServiceClient
from pdo.service_client.generic import MessageException
from pdo.common.keys import EnclaveKeys

class EnclaveServiceClient(GenericServiceClient) :

    def __init__(self, url) :
        super().__init__(url)
        enclave_info = self.get_enclave_public_info()
        self.enclave_keys = EnclaveKeys(enclave_info['verifying_key'], enclave_info['encryption_key'])

    @property
    def verifying_key(self) :
        self.enclave_keys.verifying_key

    @property
    def encryption_key(self) :
        self.enclave_keys.encryption_key

    @property
    def enclave_id(self) :
        return self.enclave_keys.identity

    # -----------------------------------------------------------------
    # encrypted_session_key -- base64 aes key encrypted with enclave's rsa key
    # encrypted_request -- base64 string encrypted with aes session key
    # -----------------------------------------------------------------
    def send_to_contract(self, encrypted_session_key, encrypted_request) :
        request = { 'operation' : 'UpdateContractRequest' }
        request['encrypted_session_key'] = encrypted_session_key
        request['encrypted_request'] = encrypted_request

        try :
            response = self._postmsg(request)
            return response['result']

        except MessageException as me :
            logger.warn('unable to contact enclave service (update_contract); %s', me)
            return None

        except :
            logger.exception('update_contract')
            return None

    # -----------------------------------------------------------------
    # contract_id -- 16 character, hex encoded, sha256 hashed, registration transaction signature
    # creator_id -- base64 encoded, sha256 hashed, creator verifying key
    # secret_list -- array of dictionaries, dictionary defines values for pspk and encrypted_secret
    # -----------------------------------------------------------------
    def verify_secrets(self, contract_id, owner_id, secret_list) :
        request = { 'operation' : 'VerifySecretRequest' }
        request['contract_id'] = contract_id
        request['creator_id'] = owner_id
        request['secrets'] = secret_list

        try :
            return self._postmsg(request)

        except KeyError as ke :
            logger.error('response missing required field; %s', ke)
            return None

        except MessageException as me :
            logger.warn('unable to contact enclave service (verify_secrets); %s', me)
            return None

        except :
            logger.exception('verify_secrets')
            return None

    # -----------------------------------------------------------------
    def get_enclave_public_info(self) :
        request = { 'operation' : 'EnclaveDataRequest' }

        try :
            return self._postmsg(request)

        except MessageException as me :
            logger.warn('unable to contact enclave service (get_enclave_info); %s', me)
            return None

        except :
            logger.exception('get_enclave_info')
            return None
