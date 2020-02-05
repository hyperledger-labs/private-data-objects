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
import random

import pdo.common.crypto as crypto
import pdo.common.keys as keys

from pdo.contract.response import ContractResponse
from pdo.contract.message import ContractMessage
from pdo.contract.state import ContractState
from pdo.submitter.create import create_submitter
import pdo.service_client.service_data.eservice as eservice_db

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

    # a monotonic counter used locally by the client to identify all its
    # requests. every (contract_id, statehash) pair maps to a unique
    # request_number. the converse is not true (if the request failed)
    __request_number__ = 0


    # -------------------------------------------------------
    def __init__(self, operation, request_originator_keys, contract, **kwargs) :
        if not self.__ops__[operation] :
            raise ValueError('invalid operation')

        self.operation = operation
        self.contract_id = contract.contract_id
        self.creator_id = contract.creator_id
        self.enclave_service = kwargs.get('enclave_service')
        if self.enclave_service == 'random':
            enclave_id = random.choice(list(contract.enclave_map.keys()))
            try: #use the eservice database to get the client
                einfo = eservice_db.get_by_enclave_id(enclave_id)
                self.enclave_service = einfo.client
            except Exception as e:
                raise Exception('failed to get enclave client using database: %s', str(e))

        self.encrypted_state_encryption_key = contract.get_state_encryption_key(self.enclave_service.enclave_id)
        self.originator_keys = request_originator_keys
        self.make_channel_keys()
        self.session_key = crypto.SKENC_GenerateKey()
        self.contract_code = contract.contract_code
        self.contract_state = contract.contract_state
        self.message = ContractMessage(self.originator_keys, self.channel_id, **kwargs)
        self.replication_params = contract.replication_params
        self.request_number = ContractRequest.__request_number__
        ContractRequest.__request_number__+=1

    # -------------------------------------------------------
    def make_channel_keys(self, ledger_type=os.environ.get('PDO_LEDGER_TYPE')):
        if ledger_type=='sawtooth':
            self.channel_keys =  keys.TransactionKeys()
            self.channel_id = self.channel_keys.txn_public
        elif ledger_type=='ccf':
            self.channel_keys =  crypto.random_bit_string(64) # byte array
            self.channel_id = crypto.byte_array_to_base64(crypto.compute_message_hash(self.channel_keys))
        else:
            raise Exception("Invalid Ledger Type. Must be either sawtooth or ccf.")

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

        if self.operation == 'initialize' :
            result['ContractCode'] = self.contract_code.serialize()
        else :
            result['ContractCodeHash'] = self.contract_code.compute_hash(encoding='b64')
            result['ContractStateHash'] = self.contract_state.get_state_hash(encoding='b64')

        result['ContractMessage'] = self.message.serialize()

        return json.dumps(result)

    # -------------------------------------------------------
    def evaluate(self) :
        """
        evaluate the request using the enclave service
        """

        # Encrypt the request
        serialized_byte_array = crypto.string_to_byte_array(self.__serialize_for_encryption())
        encrypted_request = bytes(crypto.SKENC_EncryptMessage(self.session_key, serialized_byte_array))
        encrypted_key = bytes(self.enclave_keys.encrypt(self.session_key))

        try :
            self.contract_state.push_state_to_eservice(self.enclave_service)
            encrypted_response = self.enclave_service.send_to_contract(encrypted_key, encrypted_request)

        except Exception as e:
            logger.warn('contract invocation failed; %s', str(e))
            raise InvocationException('contract invocation failed') from e

        try :
            decrypted_response = crypto.SKENC_DecryptMessage(self.session_key, encrypted_response)
        except Exception as e:
            logger.exception('failed to decrypt response; %s', encrypted_response)
            raise InvocationException('contract response cannot be decrypted')

        try :
            response_string = crypto.byte_array_to_string(decrypted_response)
            response_parsed = json.loads(response_string[0:-1])

            logger.debug("parsed response: %s", response_parsed)

            contract_response = ContractResponse(self, response_parsed)
        except Exception as e:
            logger.exception('contract response is invalid; %s', str(e))
            raise InvocationException('contract response is invalid') from e

        return contract_response
