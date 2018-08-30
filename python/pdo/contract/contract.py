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
import errno
import json

import pdo.common.crypto as crypto
import pdo.common.keys as keys
import pdo.common.utility as putils

from pdo.submitter.submitter import Submitter
from pdo.contract.request import ContractRequest
from pdo.contract.state import ContractState
from pdo.contract.code import ContractCode

import sawtooth.helpers.pdo_connect

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class Contract(object) :
    # -------------------------------------------------------
    @classmethod
    def read_from_file(cls, ledger_config, basename, data_dir = './data') :
        filename = putils.build_file_name(basename, data_dir, '.pdo')
        logger.debug('load contract information from %s', filename)
        if os.path.exists(filename) is not True :
            raise FileNotFoundError(errno.ENOENT, "contract data file does not exist", filename)

        try :
            with open(filename, "r") as contract_file :
                contract_info = json.load(contract_file)
        except Exception as e :
            logger.warn('load contract information file failed; %s', str(e))
            raise Exception("invalid contract file; {}".format(filename))

        try :
            code_info = contract_info['contract_code']
            code = ContractCode(code_info['Code'], code_info['Name'], code_info['Nonce'])
        except KeyError as ke :
            logger.error('invalid contract data file; missing %s', str(ke))
            raise Exception("invalid contract file; {}".format(filename))
        except Exception as e :
            logger.error('error occurred retreiving contract code; %s', str(e))
            raise Exception("invalid contract file; {}".format(filename))

        ## need to handle the case where the contract has been registered
        ## but the initial state has not been committed

        try :
            contract_id = contract_info['contract_id']
            current_state_hash = ContractState.get_current_state_hash(ledger_config, contract_id)
        except Exception as e :
            logger.error('error occurred retreiving contract state hash; %s', str(e))
            raise Exception('invalid contract file; {}'.format(filename))

        try :
            state = ContractState.read_from_cache(contract_id, current_state_hash, data_dir=data_dir)
            if state is None :
                state = ContractState.get_from_ledger(ledger_config, contract_id, current_state_hash)
                state.save_to_cache(data_dir=data_dir)
        except Exception as e :
            logger.error('error occurred retreiving contract state; %s', str(e))
            raise Exception("invalid contract file; {}".format(filename))

        obj = cls(code, state, contract_info['contract_id'], contract_info['creator_id'])
        for enclave in contract_info['enclaves_info'] :
            obj.set_state_encryption_key(
                enclave['contract_enclave_id'],
                enclave['encrypted_contract_state_encryption_key'])

        return obj

    # -------------------------------------------------------
    def __init__(self, code, state, contract_id, creator_id, **kwargs) :
        assert state.contract_id == contract_id

        self.contract_code = code
        self.contract_state = state
        self.contract_id = contract_id
        self.creator_id = creator_id

        self.enclave_map = kwargs.get('enclave_map',{})

    # -------------------------------------------------------
    def set_state_encryption_key(self, enclave_id, encrypted_state_encryption_key) :
        self.enclave_map[enclave_id] = encrypted_state_encryption_key

    # -------------------------------------------------------
    def get_state_encryption_key(self, enclave_id) :
        return self.enclave_map[enclave_id];

    # -------------------------------------------------------
    @property
    def provisioned_enclaves(self) :
        return list(self.enclave_map.keys())

    # -------------------------------------------------------
    # state -- base64 encoded, encrypted state
    def set_state(self, state) :
        self.contract_state.encrypted_state = state

    # -------------------------------------------------------
    def create_initialize_request(self, request_originator_keys, enclave_service,**kwargs) :
        """create a request to initialize the state of the contract

        :param request_originator_keys: object of type ServiceKeys
        :param enclave_service: object that implements the enclave service interface
        """
        return ContractRequest(
            'initialize',
            request_originator_keys,
            enclave_service,
            self,
            **kwargs)

    # -------------------------------------------------------
    def create_update_request(self, request_originator_keys, enclave_service, expression) :
        """create a request to update the state of the contract

        :param request_originator_keys: object of type ServiceKeys
        :param enclave_service: object that implements the enclave service interface
        :param expression: string, the expression to send to the contract
        """
        return ContractRequest(
            'update',
            request_originator_keys,
            enclave_service,
            self,
            expression = expression)

    # -------------------------------------------------------
    def save_to_file(self, basename, data_dir = "./data") :
        serialized = dict()
        serialized['contract_id'] = self.contract_id
        serialized['creator_id'] = self.creator_id
        try :
           serialized['contract_code'] = self.contract_code.serialize()
        except :
           serialized['contract_code'] = ""

        # this encoding is rather verbose, but mirrors the one that the ledger
        # currently uses
        enclaves_info = []
        for (enclave_id, encrypted_key) in self.enclave_map.items() :
            enclave_info = {}
            enclave_info['contract_enclave_id'] = enclave_id
            enclave_info['encrypted_contract_state_encryption_key'] = encrypted_key
            enclaves_info.append(enclave_info)

        serialized['enclaves_info'] = enclaves_info

        filename = putils.build_file_name(basename, data_dir, '.pdo')
        try :
            with open(filename, "w") as contract_file :
                json.dump(serialized, contract_file)
        except Exception as e :
            logger.warn('failed to save contract information; %s', str(e))
            raise Exception('unable to write contract data file {}'.format(filename))

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def register_contract(
        ledger_config,
        creator_keys,
        contract_code,
        provisioning_service_ids,
        **extra_params) :

    txn_keys = keys.TransactionKeys()

    if 'wait' not in extra_params :
        extra_params['wait'] = 60

    ss = Submitter(ledger_config['LedgerURL'], key_str = txn_keys.txn_private)
    txnsignature = ss.submit_contract_registration_from_data(
        creator_keys.signing_key,
        creator_keys.verifying_key,
        txn_keys.txn_public,
        crypto.byte_array_to_base64(contract_code.compute_hash()),
        provisioning_service_ids,
        **extra_params
    )

    contract_id = putils.from_transaction_signature_to_id(txnsignature)

    return contract_id

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def add_enclave_to_contract(
        ledger_config,
        creator_keys,
        contract_id,
        enclave_id,
        secrets,
        encrypted_state_encryption_key,
        signature,
        **extra_params):

    txn_keys = keys.TransactionKeys()

    enclave_secret_data_array = []
    enclave_secret_data = dict()
    enclave_secret_data['contract_id'] = contract_id
    enclave_secret_data['contract_enclave_id'] = enclave_id
    enclave_secret_data['encrypted_state_encryption_key'] = encrypted_state_encryption_key
    enclave_secret_data['signature'] = signature

    secret_list = []
    for secret in secrets :
        secret_list.append(secret)
    enclave_secret_data['provisioning_key_state_secret_pairs'] = secret_list
    enclave_secret_data_array.append(enclave_secret_data)

    if 'wait' not in extra_params :
        extra_params['wait'] = 60

    ss = Submitter(ledger_config['LedgerURL'], key_str = txn_keys.txn_private)
    txnsignature = ss.submit_add_enclave_from_data(
        creator_keys.signing_key,
        txn_keys.txn_public,
        contract_id,
        enclave_secret_data_array,
        **extra_params)

    return txnsignature
