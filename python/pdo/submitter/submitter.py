# Copyright 2020 Intel Corporation
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
import logging
from abc import ABCMeta, abstractmethod

logger = logging.getLogger(__name__)

class Submitter(object):

    __metaclass__ = ABCMeta

    def __init__(self, ledger_config, *args, **kwargs):

        self.url = ledger_config.get('LedgerURL','http://localhost:6600')
        self.pdo_signer = kwargs.get('pdo_signer', None) #PDO payload signer

# -----------------------------------------------------------------
# Following APIs are provided by the ledger submitter. These must be overridden by child class
# (CCFSubmitter). The purpose of having these as abstract methods
# is to fix the APIs. Future plans include unifying some aspects of implementation under
# the parent method (like unifying JSON payload schema)

# Following methods change the ledger state
# -----------------------------------------------------------------
    @abstractmethod
    def register_encalve(self,
        enclave_verifying_key,
        enclave_encryption_key,
        proof_data,
        registration_block_context,
        organizational_info,
        **extra_params):
        """ return txn_id """
        raise NotImplementedError("Must override register_encalve")

# -----------------------------------------------------------------
    @abstractmethod
    def register_contract(self,
        contract_code_hash,
        provisioning_service_ids,
        **extra_params):
        """ return txn_id """
        raise NotImplementedError("Must override register_contract")

# -----------------------------------------------------------------
    @abstractmethod
    def add_enclave_to_contract(self,
        contract_id,
        enclave_info_quintuples,
        **extra_params):
        """ return txn_id """
        raise NotImplementedError("Must override add_enclave_to_contract")

# -----------------------------------------------------------------
    @abstractmethod
    def ccl_initialize(self,
        channel_key,
        contract_enclave_id,
        enclave_signature,
        contract_id,
        contract_code_hash,
        message_hash,
        initial_state_hash,
        contract_metadata_hash,
        **extra_params):
        """ return txn_id """
        raise NotImplementedError("Must override ccl_initialize")

# -----------------------------------------------------------------
    @abstractmethod
    def ccl_update(self,
        channel_key,
        contract_enclave_id,
        enclave_signature,
        contract_id,
        message_hash,
        current_state_hash,
        previous_state_hash,
        dependency_list,
        **extra_params):
        """ return txn_id """
        raise NotImplementedError("Must override ccl_update")

# Following methods read from the ledger
# -----------------------------------------------------------------
    @abstractmethod
    def get_enclave_info(self,
        enclave_id):
        """ return dict with the following keys:
                verifying_key,
                encryption_key,
                owner_id,
                last_registration_block_context,
                proof_data
        """
        raise NotImplementedError("Must override get_enclave_info")

# -----------------------------------------------------------------
    @abstractmethod
    def get_ledger_info(self):
        """ return ledger_verifying_key
        """
        raise NotImplementedError("Must override get_ledger_info")

# -----------------------------------------------------------------
    @abstractmethod
    def get_contract_info(self,
        contract_id):
        """ return dict with the following keys:
                pdo_contract_creator_pem_key,
                contract_code_hash
        """
        raise NotImplementedError("Must override get_contract_info")

# -----------------------------------------------------------------
    @abstractmethod
    def get_contract_provisioning_info(self,
        contract_id):
        """ return dict with the following keys:
                pdo_contract_creator_pem_key,
                provisioning_service_ids,
                enclaves_info
        """
        raise NotImplementedError("Must override get_contract_info")

# -----------------------------------------------------------------
    @abstractmethod
    def get_current_state_hash(self,
        contract_id):
        """ return dict with the following keys:
                state_hash,
                is_active
        """
        raise NotImplementedError("Must override get_current_state_hash_for_contract")

# -----------------------------------------------------------------
    @abstractmethod
    def get_state_details(self,
        contract_id,
        state_hash):
        """ return dict with the following keys:
                transaction_id,
                previous_state_hash,
                message_hash,
                dependency_list
        """
        raise NotImplementedError("Must override get_state_details")

#---------------------------------------------------------------
#Common Internal Functions
#---------------------------------------------------------------
def get_epid_pseudonym_from_proof_data(proof_data):
    pj = json.loads(proof_data)
    vj = json.loads(pj['verification_report'])
    return vj['epidPseudonym']
