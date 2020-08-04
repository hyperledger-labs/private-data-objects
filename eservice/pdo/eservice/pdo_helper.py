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

from pdo.submitter.create import create_submitter

import logging
logger = logging.getLogger(__name__)

__all__ = [ "Enclave", "initialize_enclave", "shutdown_enclave", "parse_enclave_policy" ]

# helper function to read list of .pem key files
def __parse_pem_file_list(key_list, search_path):
    keys = []
    for key_file in key_list:
        logger.debug('opening key file %s', key_file)
        full_file = putils.find_file_in_path(key_file, search_path)
        with open(full_file, 'r') as k:
            key = k.read()
        assert key.startswith('-----BEGIN PUBLIC KEY-----\n') and key.endswith('\n-----END PUBLIC KEY-----\n'), "Malformed .pem key"
        keys.append(key)
    return keys

def parse_enclave_policy(policy_config, key_path):
    enclave_policy = { "AcceptAllCode" : policy_config['AcceptAllCode'] } # convert str to bool
    enclave_policy["TrustedCompilerKeys"] = __parse_pem_file_list(policy_config['TrustedCompilerKeys'], key_path)
    enclave_policy["TrustedLedgerKey"] = policy_config['TrustedLedgerKey']
    return enclave_policy

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def initialize_enclave(config) :
    """initialize_enclave -- call the initialization function on the
    enclave module
    """
    try :
        block_store_file = config['StorageService']['BlockStore']
        if not os.path.isfile(block_store_file) :
            raise Exception('missing block store file {0}'.format(block_store_file))

        pdo_enclave.block_store_open(block_store_file)
    except KeyError as ke :
        raise Exception('missing block store configuration key {0}'.format(str(ke)))

    try :
        enclave_config = config['EnclaveModule']
        # add the enclave policy
        enclave_config['EnclavePolicy'] = parse_enclave_policy(config['EnclavePolicy'], config['Key']['SearchPath'])
        pdo_enclave.initialize_with_configuration(enclave_config)
    except KeyError as ke :
        raise Exception('missing enclave module configuration')

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def shutdown_enclave() :
    """
    """
    try :
        pdo_enclave.shutdown()
    except Exception as e :
        logger.error('enclave shutdown failed; %s', str(e))

    try :
        pdo_enclave.block_store_close()
    except Exception as e :
        logger.error('block store shutdown failed; %s', str(e))

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def get_enclave_service_info(spid, config=None) :
    """get_enclave_service_info -- Retrieve enclave MRENCLAVE & BASENAME
    """
    return pdo_enclave.get_enclave_service_info(spid, config=config)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class Enclave(object) :
    """
    Wraps calls to the client for symmetry with the enclave service client
    """

    # -------------------------------------------------------
    @classmethod
    def read_from_file(cls, basename, data_dir = None, txn_keys = None, block_store = None) :
        """read_from_file -- read enclave data from a file and initialize a new
        Enclave object with the resulting data.

        :param file_name:  string, name of the file
        :param search_path: list of strings, directories to search for the data file
        :param txn_keys: Used to sign the register_enclave transaction. For Sawtooth,
                         this is of type TransactionKeys, while for CCF, this is of type ServiceKeys
        """
        if txn_keys is None :
            txn_keys = keys.generate_txn_keys()

        filename = putils.build_file_name(basename, data_dir = data_dir, extension = '.enc')
        if os.path.exists(filename) is not True :
            raise FileNotFoundError(errno.ENOENT, "enclave information file does not exist", filename)

        logger.debug('load enclave information from %s', filename)
        with open(filename, "r") as enclave_file :
            enclave_info = json.load(enclave_file)

        try :
            assert 'nonce' in enclave_info
            assert 'sealed_data' in enclave_info
            assert 'interpreter' in enclave_info
            assert 'verifying_key' in enclave_info
            assert 'encryption_key' in enclave_info
            assert 'proof_data' in enclave_info
            assert 'enclave_id' in enclave_info
        except KeyError as ke :
            raise Exception('enclave data missing key {0}'.format(str(ke)))
        except :
            raise Exception('invalid enclave data file {0}'.format(filename))

        try :
            public_enclave_data = pdo_enclave.get_enclave_public_info(enclave_info['sealed_data'])
            assert public_enclave_data and len(public_enclave_data) == 2
            assert enclave_info['verifying_key'] == public_enclave_data['verifying_key']
            assert enclave_info['encryption_key'] == public_enclave_data['encryption_key']
        except :
            raise Exception('sealed storage does not match enclave data file; {}'.format(filename))

        return cls(enclave_info, txn_keys, block_store)

    # -------------------------------------------------------
    @classmethod
    def create_new_enclave(cls, txn_keys = None, block_store = None) :
        """create_new_enclave -- create a new enclave

        :param txn_keys: Used to sign the register_enclave transaction. For Sawtooth,
                         this is of type TransactionKeys, while for CCF, this is of type ServiceKeys
        """
        if txn_keys is None :
            txn_keys = keys.generate_txn_keys()

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
        enclave_info['interpreter'] = enclave_data.interpreter
        enclave_info['verifying_key'] = enclave_data.verifying_key
        enclave_info['encryption_key'] = enclave_data.encryption_key
        enclave_info['enclave_id'] = enclave_data.verifying_key
        enclave_info['proof_data'] = ''
        if not pdo_enclave.enclave.is_sgx_simulator() :
            enclave_info['proof_data'] = enclave_data.proof_data

        return cls(enclave_info, txn_keys, block_store)

    # -------------------------------------------------------
    def __init__(self, enclave_info, txn_keys, block_store = None) :

        # initialize the keys that can be used later to
        # register the enclave with the ledger
        self.txn_keys = txn_keys
        try :
            self.nonce = enclave_info['nonce']
            self.sealed_data = enclave_info['sealed_data']
            self.interpreter = enclave_info['interpreter']
            self.verifying_key = enclave_info['verifying_key']
            self.encryption_key = enclave_info['encryption_key']
            self.proof_data = enclave_info['proof_data']
            self.enclave_id = enclave_info['enclave_id']
        except KeyError as ke :
            raise Exception("missing enclave initialization parameter; {}".format(str(ke)))

        self.enclave_keys = keys.EnclaveKeys(self.verifying_key, self.encryption_key)

        if block_store :
            self.attach_block_store(block_store)

    # -------------------------------------------------------
    def attach_block_store(self, block_store) :
        self.get_block = block_store.get_block
        self.get_blocks = block_store.get_blocks
        self.store_block = block_store.store_block
        self.store_blocks = block_store.store_blocks
        self.check_block = block_store.check_block
        self.check_blocks = block_store.check_blocks

    # -------------------------------------------------------
    def send_to_contract(self, encrypted_session_key, encrypted_request) :

        """
        send a contract update request to the enclave

        :param encrypted_session_key: byte array, encrypted AES key
        :param encrypted_request: byte array, encrypted contract request
        """
        try :
            return pdo_enclave.send_to_contract(
                self.sealed_data,
                encrypted_session_key,
                encrypted_request)

        except Exception as e :
            logger.error('send_to_contract failed; %s, %s', type(e), str(e.args))
            raise

    # -------------------------------------------------------
    def send_to_contract_encoded(self, encrypted_session_key, encrypted_request) :

        """
        send a contract update request to the enclave

        :param encrypted_session_key: base64 encoded encrypted AES key
        :param encrypted_request: base64 encoded encrypted contract request
        """
        try :
            return pdo_enclave.send_to_contract_encoded(
                self.sealed_data,
                encrypted_session_key,
                encrypted_request)

        except Exception as e :
            logger.error('send_to_contract failed; %s, %s', type(e), str(e.args))
            raise

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
    def save_to_file(self, basename, data_dir = None) :
        enclave_info = dict()
        enclave_info['nonce'] = self.nonce
        enclave_info['sealed_data'] = self.sealed_data
        enclave_info['verifying_key'] = self.verifying_key
        enclave_info['encryption_key'] = self.encryption_key
        enclave_info['proof_data'] = self.proof_data
        enclave_info['enclave_id'] = self.enclave_id

        filename = putils.build_file_name(basename, data_dir=data_dir, extension='.enc')
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

            submitter = create_submitter(ledger_config, pdo_signer = self.txn_keys)

            txnsignature = submitter.register_encalve(
                self.verifying_key,
                self.encryption_key,
                self.proof_data,
                self.nonce, # registration block content
                ledger_config.get('Organization', "EMPTY")) # Eservice Organization Info
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
            registry_helper = create_submitter(ledger_config)
            enclave_state = registry_helper.get_enclave_info(self.enclave_id)
        except Exception as ce :
            raise Exception('failed to verify enclave registration; %s', str(ce))

        logger.info('enclave registration verified')
        return True
