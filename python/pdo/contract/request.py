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
import os
import json

import pdo.common.crypto as crypto
import pdo.common.keys as keys

from pdo.contract.response import ContractResponse
from pdo.contract.message import ContractMessage
from pdo.contract.state import ContractState
from pdo.submitter.submitter import Submitter

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ContractRequest(object) :
    __ops__ = { 'initialize' : True, 'update' : True }

    def __init__(self, operation, request_originator_keys, enclave_service, contract, **kwargs) :
        if not self.__ops__[operation] :
            raise ValueError('invalid operation')

        self.operation = operation

        self.contract_id = contract.contract_id
        self.creator_id = contract.creator_id
        self.encrypted_state_encryption_key = contract.get_state_encryption_key(enclave_service.enclave_id)
        self.enclave_service = enclave_service
        self.originator_keys = request_originator_keys
        self.channel_keys = keys.TransactionKeys()
        self.session_key = crypto.SKENC_GenerateKey()

        self.contract_code = contract.contract_code
        self.contract_state = contract.contract_state
        self.message = ContractMessage(self.originator_keys, self.channel_keys, **kwargs)

    @property
    def enclave_keys(self) :
        return self.enclave_service.enclave_keys

    def __serialize_for_encryption(self) :
        result = dict()
        result['Operation'] = self.operation
        result['ContractID'] = self.contract_id
        result['CreatorID'] = self.creator_id
        result['EncryptedStateEncryptionKey'] = self.encrypted_state_encryption_key

        result['ContractState'] = self.contract_state.serializeForInvokation()
        result['ContractCode'] = self.contract_code.serialize()
        result['ContractMessage'] = self.message.serialize()

        return json.dumps(result)

    def __encrypt_session_key(self) :
        encrypted_key = self.enclave_keys.encrypt(self.session_key)
        return crypto.byte_array_to_base64(encrypted_key)

    # response -- base64 encode, response encrypted with session key
    def __decrypt_response(self, response) :
        decoded_response = crypto.base64_to_byte_array(response)
        return crypto.SKENC_DecryptMessage(self.session_key, decoded_response)

    # enclave_service -- enclave service wrapper object
    def evaluate(self) :
        encrypted_session_key = self.__encrypt_session_key()

        # Encrypt the request
        serialized_byte_array = crypto.string_to_byte_array(self.__serialize_for_encryption())
        encrypted_request_raw = crypto.SKENC_EncryptMessage(self.session_key, serialized_byte_array)
        encrypted_request = crypto.byte_array_to_base64(encrypted_request_raw)

        try :
            # Check and conditionally put the encrypted state into the block store if it is non-empty
            state_hash_b64 = self.contract_state.getStateHash(encoding='b64')
            if state_hash_b64:
                block_store_len = self.enclave_service.block_store_head(state_hash_b64)
                if block_store_len <= 0:
                    # This block wasn't present in the block store of this enclave service - need to send it
                    logger.debug("Block store did not contain block '%s' - sending it", state_hash_b64)

                    ret = self.enclave_service.block_store_put(state_hash_b64, self.contract_state.encrypted_state)
                    if ret != True:
                        logger.exception("block_store_put failed for key %s", state_hash_b64)
                        raise

                #put rest of state in block store
                logger.debug('Sending rest of state to EService')
                #NOTICE: state_hash_b64 is the id of the self.contract_state.encrypted_state block
                #           which contains the json array of the block ids of the state
                string_main_state_block = crypto.byte_array_to_string(crypto.base64_to_byte_array(self.contract_state.encrypted_state))
                string_main_state_block = string_main_state_block.rstrip('\0')
                logger.debug("json blob in main state block: %s", string_main_state_block)
                json_main_state_block = json.loads(string_main_state_block)
                for hex_str_block_id in json_main_state_block['BlockIds']:
                    logger.debug("block id: %s", hex_str_block_id)
                    b64_block_id = crypto.byte_array_to_base64(crypto.hex_to_byte_array(hex_str_block_id))
                    cs_block = ContractState.read_from_cache(self.contract_id, b64_block_id)
                    b64_block = cs_block.encrypted_state
                    if b64_block is None :
                            raise Exception('Unable to retrieve block from cache, %s', b64_block_id)
                    block_store_len = self.enclave_service.block_store_head(b64_block_id)
                    if block_store_len <= 0:
                        # This block wasn't present in the block store of this enclave service - need to send it
                        logger.debug("Block store did NOT contain block '%s' - sending it", b64_block_id)
                        ret = self.enclave_service.block_store_put(b64_block_id, b64_block)
                        if ret != True:
                            logger.exception("block_store_put failed for state block %s -> %s", b64_block_id, b64_block)
                            raise
                        else:
                            logger.debug("Block store DID contain block '%s' - skip send", b64_block_id)

            encoded_encrypted_response = self.enclave_service.send_to_contract(encrypted_session_key, encrypted_request)
            if encoded_encrypted_response == None:
                logger.exception("send_to_contract failed but no exception was thrown")
                raise

            logger.debug("raw response from enclave: %s", encoded_encrypted_response)
        except :
            logger.exception('contract invocation failed')
            raise

        try :
            decrypted_response = self.__decrypt_response(encoded_encrypted_response)
            response_string = crypto.byte_array_to_string(decrypted_response)
            response_parsed = json.loads(response_string[0:-1])

            logger.debug("parsed response: %s", response_parsed)

            contract_response = ContractResponse(self, response_parsed)
        except Exception as e:
            logger.exception('contract response is invalid: ' + str(e))
            raise

        return contract_response
