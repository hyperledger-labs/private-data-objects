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
class InvocationException(Exception) :
    """
    A class to capture invocation exceptions
    """
    pass

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ContractRequest(object) :
    __ops__ = { 'initialize' : True, 'update' : True }

    # -------------------------------------------------------
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

    # -------------------------------------------------------
    @property
    def enclave_keys(self) :
        return self.enclave_service.enclave_keys

    # -------------------------------------------------------
    def __serialize_for_encryption(self) :
        result = dict()
        result['Operation'] = self.operation
        result['ContractID'] = self.contract_id
        result['CreatorID'] = self.creator_id
        result['EncryptedStateEncryptionKey'] = self.encrypted_state_encryption_key

        result['ContractState'] = self.contract_state.serialize_for_invocation()
        result['ContractCode'] = self.contract_code.serialize()
        result['ContractMessage'] = self.message.serialize()

        return json.dumps(result)

    # -------------------------------------------------------
    def __encrypt_session_key(self) :
        encrypted_key = self.enclave_keys.encrypt(self.session_key)
        return crypto.byte_array_to_base64(encrypted_key)

    # -------------------------------------------------------
    def __decrypt_response(self, response) :
        """
        decrypt the response using the session key

        :param response string: base64 encoded, encrypted with session key
        """
        decoded_response = crypto.base64_to_byte_array(response)
        return crypto.SKENC_DecryptMessage(self.session_key, decoded_response)

    # -------------------------------------------------------
    def evaluate(self) :
        """
        evaluate the request using the enclave service
        """
        encrypted_session_key = self.__encrypt_session_key()

        # Encrypt the request
        serialized_byte_array = crypto.string_to_byte_array(self.__serialize_for_encryption())
        encrypted_request_raw = crypto.SKENC_EncryptMessage(self.session_key, serialized_byte_array)
        encrypted_request = crypto.byte_array_to_base64(encrypted_request_raw)

        try :
            self.contract_state.push_state_to_eservice(self.enclave_service)

            encoded_encrypted_response = self.enclave_service.send_to_contract(encrypted_session_key, encrypted_request)
            logger.debug("raw response from enclave: %s", encoded_encrypted_response)

        except Exception as e:
            logger.warn('contract invocation failed; %s', str(e))
            raise InvocationException('contract invocation failed') from e

        try :
            decrypted_response = self.__decrypt_response(encoded_encrypted_response)
            response_string = crypto.byte_array_to_string(decrypted_response)
            response_parsed = json.loads(response_string[0:-1])

            logger.debug("parsed response: %s", response_parsed)

            contract_response = ContractResponse(self, response_parsed)
        except Exception as e:
            logger.exception('contract response is invalid; %s', str(e))
            raise InvocationException('contract response is invalid') from e

        return contract_response
