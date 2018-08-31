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

"""enclave.py

This file defines the Enclave class to simplify integration of the SGX
enclave module into the rest of the PDO flow. Typically, an application
will call the initialize_enclave function first, then will call either
read_from_file or create_new_enclave depending on whether a new or
existing enclave is being connected. Then the enclave can be registered
with the ledger with register_enclave or the registation verified with
verify_registration

"""

import os
import json
import random
import errno

import pdo.eservice.pdo_enclave as pdo_enclave

import pdo.common.keys as keys
import pdo.common.crypto as crypto
import pdo.common.utility as putils

from pdo.submitter.submitter import Submitter
import sawtooth.helpers.pdo_connect
from pdo.contract import code as pdo_code 
import logging
logger = logging.getLogger(__name__)

__all__ = [ "Enclave", "initialize_enclave" ]


# -----------------------------------------------------------------
# -----------------------------------------------------------------
def initialize_enclave(enclave_config) :
    """initialize_enclave -- call the initialization function on the
    enclave module
    """
    pdo_enclave.initialize_with_configuration(enclave_config)
# -----------------------------------------------------------------
# -----------------------------------------------------------------
class Enclave(object) :
    """
    Wraps calls to the client for symmetry with the enclave service client
    """

    # -------------------------------------------------------
    @classmethod
    def read_from_file(cls, basename, data_dir = './data', txn_keys = None) :
        """read_from_file -- read enclave data from a file and initialize a new
        Enclave object with the resulting data.

        :param file_name:  string, name of the file
        :param search_path: list of strings, directories to search for the data file
        :param txn_keys: object of type TransactionKeys
        """

        if txn_keys is None :
            txn_keys = keys.TransactionKeys()

        filename = os.path.realpath(os.path.join(data_dir, basename + ".enc"))
        logger.debug('load enclave information from %s', filename)
        if os.path.exists(filename) is not True :
            raise FileNotFoundError(errno.ENOENT, "enclave information file does not exist", filename)

        with open(filename, "r") as enclave_file :
            enclave_info = json.load(enclave_file)

        try :
            assert 'nonce' in enclave_info
            assert 'sealed_data' in enclave_info
            assert 'verifying_key' in enclave_info
            assert 'encryption_key' in enclave_info
            assert 'proof_data' in enclave_info
            assert 'enclave_id' in enclave_info
        except KeyError as ke :
            raise Exception('enclave data missing key {0}'.format(str(ke)))
        except :
            raise Exception('invalid enclave data file {0}'.format(full_name))

        try :
            public_enclave_data = pdo_enclave.get_enclave_public_info(enclave_info['sealed_data'])
            assert public_enclave_data and len(public_enclave_data) == 2
            assert enclave_info['verifying_key'] == public_enclave_data['verifying_key']
            assert enclave_info['encryption_key'] == public_enclave_data['encryption_key']
        except :
            raise Exception('sealed storage does not match enclave data file; {}'.format(full_name))

        return cls(enclave_info, txn_keys)

    # -------------------------------------------------------
    @classmethod
    def create_new_enclave(cls, txn_keys = None) :
        """create_new_enclave -- create a new enclave

        :param txn_keys: object of type TransactionKeys
        """

        if txn_keys is None :
            txn_keys = keys.TransactionKeys()

        nonce = '{0:016X}'.format(random.getrandbits(64))
        hashed_identity = txn_keys.hashed_identity
        logger.debug("tx hashed identity: %s", hashed_identity)
        try :
            enclave_data = pdo_enclave.create_signup_info(hashed_identity, nonce)
        except :
            raise Exception('failed to create enclave signup data')

        enclave_info = dict()
        enclave_info['nonce'] = nonce
        enclave_info['sealed_data'] = enclave_data.sealed_signup_data
        enclave_info['verifying_key'] = enclave_data.verifying_key
        enclave_info['encryption_key'] = enclave_data.encryption_key
        enclave_info['enclave_id'] = enclave_data.verifying_key
        enclave_info['proof_data'] = ''
        if not pdo_enclave.enclave.is_sgx_simulator() :
            enclave_info['proof_data'] = enclave_data.proof_data

        return cls(enclave_info, txn_keys)

    # -------------------------------------------------------
    def __init__(self, enclave_info, txn_keys) :

        # initialize the keys that can be used later to
        # register the enclave with the ledger
        self.txn_keys = txn_keys

        try :
            self.nonce = enclave_info['nonce']
            self.sealed_data = enclave_info['sealed_data']
            self.verifying_key = enclave_info['verifying_key']
            self.encryption_key = enclave_info['encryption_key']
            self.proof_data = enclave_info['proof_data']
            self.enclave_id = enclave_info['enclave_id']
        except KeyError as ke :
            raise Exception("missing enclave initialization parameter; {}".format(str(ke)))

        self.enclave_keys = keys.EnclaveKeys(self.verifying_key, self.encryption_key)

    # -------------------------------------------------------
    def send_to_contract(self, encrypted_session_key, encrypted_request) :

        """
        send a contract update request to the enclave

        :param encrypted_session_key: base64 encoded encrypted AES key
        :param encrypted_request: base64 encoded encrypted contract request
        """
        return pdo_enclave.send_to_contract(
            self.sealed_data,
            encrypted_session_key,
            encrypted_request)

    # -------------------------------------------------------
    def verify_secrets(self, contract_id, owner_id, secret_list) :
        """
        request that the enclave create a state encryption key from
        the provided provisioning service secrets.

        :param contract_id: contract identity (hash of registration signature)
        :param owner_id: owner's identity (verifying key in PEM format)
        "param secret_list: array of dictionaries, each with pspk and encrypted secret
        """
        return pdo_enclave.verify_secrets(
            self.sealed_data,
            contract_id,
            owner_id,
            json.dumps(secret_list))

    # -------------------------------------------------------
    def get_enclave_public_info(self) :
        """
        return information about the enclave; we could short circuit
        this and just send back the data that is stored
        """
        return pdo_enclave.get_enclave_public_info(self.sealed_data)

    # -------------------------------------------------------
    def save_to_file(self, basename, data_dir = "./data") :
        enclave_info = dict()
        enclave_info['nonce'] = self.nonce
        enclave_info['sealed_data'] = self.sealed_data
        enclave_info['verifying_key'] = self.verifying_key
        enclave_info['encryption_key'] = self.encryption_key
        enclave_info['proof_data'] = self.proof_data
        enclave_info['enclave_id'] = self.enclave_id

        filename = os.path.realpath(os.path.join(data_dir, basename + ".enc"))
        logger.debug('save enclave data to %s', filename)
        with open(filename, "w") as file :
            json.dump(enclave_info, file)

    # -------------------------------------------------------
    def register_enclave(self, ledger_config) :
        """
        register the enclave with the sawtooth ledger

        :param ledger_config: dictionary of configuration information that must include LedgerURL
        """
        try :
            logger.debug('submit enclave registration to %s', ledger_config['LedgerURL'])

            submitter = Submitter(
                ledger_config['LedgerURL'],
                key_str = self.txn_keys.txn_private)

            txnsignature = submitter.submit_enclave_registration_from_data(
                self.verifying_key,
                self.encryption_key,
                self.proof_data,
                self.nonce,
                ledger_config.get('Organization', "EMPTY"),
                wait=30.0)
        except TimeoutError as err :
            raise Exception('time out waiting for ledger commit')
        except Exception as e :
            logger.error('failed to register enclave; %s', str(e))
            raise
        return txnsignature

    # -------------------------------------------------------
    def verify_registration(self, ledger_config) :
        """
        verify that the enclave is registered with the ledger

        :param ledger_config: dictionary of configuration information that must include LedgerURL
        """
        try:
            client = sawtooth.helpers.pdo_connect.PdoClientConnectHelper(
                ledger_config['LedgerURL'],
                key_str = self.txn_keys.txn_private)
            enclave_state = client.get_enclave_dict(self.enclave_id)
        except sawtooth.helpers.pdo_connect.ClientConnectException as ce :
            raise Exception('failed to verify enclave registration; %s', str(ce))
        except:
            raise Exception('unknown error occurred while verifying enclave registration')

        logger.info('enclave registration verified')
        return True
