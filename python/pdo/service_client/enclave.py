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

    # -----------------------------------------------------------------
    def block_store_head(self, state_hash_b64) :
        """
        Checks if a block is present in the block store.
        Returns:
            int(length) if present
            -1 if not present
            None on error
        """
        request = { 'operation' : 'BlockStoreHeadRequest' }
        request['key'] = state_hash_b64

        try :
            response = self._postmsg(request)
            return int(response['length'])

        except MessageException as me :
            logger.warn('unable to contact enclave service (block_store_head); %s', me)
            return None

        except :
            logger.exception('block_store_head')
            return None

    # -----------------------------------------------------------------
    def block_store_get(self, state_hash_b64) :
        """
        Retrieves a block from the enclave service's block store
        Returns:
            base64 encoded block data
            None on error
        """
        request = { 'operation' : 'BlockStoreGetRequest' }
        request['key'] = state_hash_b64

        try :
            response = self._postmsg(request)
            return response['result']

        except MessageException as me :
            logger.warn('unable to contact enclave service (block_store_get); %s', me)
            return None

        except :
            logger.exception('block_store_get')
            return None

    # -----------------------------------------------------------------
    def block_store_put(self, state_hash_b64, state_b64) :
        """
        Retrieves a block from the enclave service's block store
        Returns:
            True - Success
            False - Failure
        """
        request = { 'operation' : 'BlockStorePutRequest' }
        request['key'] = state_hash_b64
        request['value'] = state_b64

        try :
            response = self._postmsg(request)
            return True

        except MessageException as me :
            logger.warn('unable to contact enclave service (block_store_put); %s', me)
            return False

        except :
            logger.exception('block_store_put')
            return False

    # --------------------------------------------------
    def get_state_block_list_and_cache(b64_state_hash) :
        """
        Retrieves the current state block list
        :param b64_state_hash: the base64 encoding of the state hash
        """
        # ba = byte_array ; baa = byte_array_array
        ba_state_hash = crypto.base64_to_byte_array(b64_state_hash)
        while True:
            baa_block_id_list = STATE_GetStateBlockList(b64_state_hash)
            #either we have the block list, or a block is missing
            if(not baa_block_id_list):
                ba_missing_block_id = STATE_GetMissingBlock()
                b64_missing_block_id = crypto.byte_array_to_base64(ba_missing_block_id)
                b64_block = self.enclave_service.block_store_get(b64_missing_block_id)
                logger.debug('missing block  %s', b64_missing_block_id)
                STATE_WarmUpCache(b64_missing_block_id, b64_block)
            else:
                break

        #dump list
        logger.debug('Dump of block list:');
        for ba_block_id in baa_block_id_list:
            logger.debug('missing block  %s', crypto.byte_array_to_hex(ba_block_id))

        return baa_block_id_list
