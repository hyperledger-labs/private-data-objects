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

    @property
    def session_iv(self) :
        return crypto.SKENC_GenerateIV(self.enclave_keys.identity)

    def __serialize_for_encryption(self) :
        result = dict()
        result['Operation'] = self.operation
        result['ContractID'] = self.contract_id
        result['CreatorID'] = self.creator_id
        result['EncryptedStateEncryptionKey'] = self.encrypted_state_encryption_key

        result['ContractState'] = self.contract_state.serialize()
        result['ContractCode'] = self.contract_code.serialize()
        result['ContractMessage'] = self.message.serialize()

        return json.dumps(result)

    def __encrypt_session_key(self) :
        encrypted_key = self.enclave_keys.encrypt(self.session_key)
        return crypto.byte_array_to_base64(encrypted_key)

    def __encrypt_request(self) :
        serialized_byte_array = crypto.string_to_byte_array(self.__serialize_for_encryption())
        encrypted_request = crypto.SKENC_EncryptMessage(self.session_key, self.session_iv, serialized_byte_array)
        return crypto.byte_array_to_base64(encrypted_request)

    # response -- base64 encode, response encrypted with session key
    def __decrypt_response(self, response) :
        decoded_response = crypto.base64_to_byte_array(response)
        return crypto.SKENC_DecryptMessage(self.session_key, self.session_iv, decoded_response)

    # enclave_service -- enclave service wrapper object
    def evaluate(self) :
        encrypted_session_key = self.__encrypt_session_key()
        encrypted_request = self.__encrypt_request()

        try :
            encoded_encrypted_response = self.enclave_service.send_to_contract(encrypted_session_key, encrypted_request)
            assert encoded_encrypted_response

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
        except :
            logger.exception('contract response is invalid')
            raise

        return contract_response
