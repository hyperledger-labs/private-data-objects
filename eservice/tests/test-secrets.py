#!/usr/bin/env python

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
import sys
import hashlib
import random
import json

import pdo.test.helpers.secrets as secret_helper
import pdo.eservice.pdo_helper as enclave_helper

import pdo.common.keys as keys
import pdo.common.crypto as crypto
import pdo.common.secrets as secrets

import logging
import pdo.common.logger as plogger

logger = logging.getLogger(__name__)

import pdo.common.config as pconfig

## -----------------------------------------------------------------
ContractHost = os.environ.get("HOSTNAME", "localhost")
ContractHome = os.environ.get("CONTRACTHOME") or os.path.realpath("/opt/pdo")
ContractEtc = os.environ.get("CONTRACTETC") or os.path.join(ContractHome, "etc")
ContractKeys = os.environ.get("CONTRACTKEYS") or os.path.join(ContractHome, "keys")
ContractLogs = os.environ.get("CONTRACTLOGS") or os.path.join(ContractHome, "logs")
ContractData = os.environ.get("CONTRACTDATA") or os.path.join(ContractHome, "data")
LedgerURL = os.environ.get("LEDGER_URL", "http://127.0.0.1:8008/")
ScriptBase = os.path.splitext(os.path.basename(sys.argv[0]))[0]

config_map = {
    'base' : ScriptBase,
    'data' : ContractData,
    'etc'  : ContractEtc,
    'home' : ContractHome,
    'host' : ContractHost,
    'keys' : ContractKeys,
    'logs' : ContractLogs,
    'ledger' : LedgerURL
}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
conffiles = [ 'eservice_tests.toml' ]
confpaths = [ ".", "./etc" ]

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--config', help='configuration file', nargs = '+')
parser.add_argument('--config-dir', help='configuration file', nargs = '+')
parser.add_argument('--loglevel', help='Set the logging level', default='INFO')
parser.add_argument('--logfile', help='Name of the log file', default='__screen__')
options = parser.parse_args()

config_map['identity'] = 'test-secrets'

try :
    config = pconfig.parse_configuration_files(conffiles, confpaths, config_map)
except pconfig.ConfigurationException as e :
    logger.error(str(e))
    sys.exit(-1)

contract_creator_keys = keys.ServiceKeys.create_service_keys()
contract_creator_id = contract_creator_keys.identity
contract_id = crypto.byte_array_to_hex(crypto.random_bit_string(256))[:32]

# -----------------------------------------------------------------
# -----------------------------------------------------------------
plogger.setup_loggers({'LogLevel' : options.loglevel.upper(), 'LogFile' : options.logfile})

# -----------------------------------------------------------------
# -----------------------------------------------------------------
enclave_helper.initialize_enclave(config.get('EnclaveModule'))
enclave_client = enclave_helper.Enclave.create_new_enclave()

# -----------------------------------------------------------------
logger.info('test correct inputs')
# -----------------------------------------------------------------
def test_secrets(secret_count) :
    global enclave_client
    global contract_id
    global contract_creator_id

    logger.info('test with secret count %d', secret_count)
    enclave_keys = enclave_client.enclave_keys

    secret_list = secret_helper.create_secret_list(
        secret_count, enclave_keys, contract_id, contract_creator_id)

    try :
        secretinfo = enclave_client.verify_secrets(contract_id, contract_creator_id, secret_list)
        assert secretinfo

        encrypted_state_encryption_key = secretinfo['encrypted_state_encryption_key']
        signature = secretinfo['signature']

    except :
        logger.exception('failed to create the state encryption key')
        sys.exit(-1)

    try :
        if not secrets.verify_state_encryption_key_signature(
                encrypted_state_encryption_key, secret_list, contract_id, contract_creator_id, signature, enclave_keys) :
            raise RuntimeError('signature verification failed')
    except :
        logger.exception('failed to verify the state encryption key')
        sys.exit(-1)

    logger.debug('encrypted state encryption key: %s', encrypted_state_encryption_key)

test_secrets(1)
test_secrets(5)
test_secrets(50)

for x in range(50) :
    test_secrets(1)

# -----------------------------------------------------------------
logger.info('test incorrect inputs')
# -----------------------------------------------------------------
enclave_keys = enclave_client.enclave_keys

# -----------------------------------------------------------------
logger.info('test with secret count 0')
logger.info('expected error: there must be at least one secret provided')
# -----------------------------------------------------------------
try:
    secretinfo = enclave_client.verify_secrets(contract_id, contract_creator_id, [])
    logger.error('failed to catch empty secret list')
    sys.exit(-1)
except :
    pass

# -----------------------------------------------------------------
logger.info('test with invalid pspk')
logger.info('expected error: count not deserialize public ECDSA key')
# -----------------------------------------------------------------
try:
    secret_list = secret_helper.create_secret_list(3, enclave_keys, contract_id, contract_creator_id)
    secret_list[0]['pspk'] = ''

    secretinfo = enclave_client.verify_secrets(contract_id, contract_creator_id, secret_list)
    logger.error('failed to catch invalid secret list')
    sys.exit(-1)
except :
    pass

# -----------------------------------------------------------------
logger.info('test with null secret')
logger.info('expected error: RSA ciphertext is invalid')
# -----------------------------------------------------------------
try:
    secret_list = secret_helper.create_secret_list(3, enclave_keys, contract_id, contract_creator_id)
    secret_list[0]['encrypted_secret'] = ''

    secretinfo = enclave_client.verify_secrets(contract_id, contract_creator_id, secret_list)
    logger.error('failed to catch invalid secret list')
    sys.exit(-1)
except :
    pass

# -----------------------------------------------------------------
logger.info('test with short secret')
logger.info('expected error: Invalid encrypted secret')
# -----------------------------------------------------------------
try:
    secret_list = secret_helper.create_secret_list(3, enclave_keys, contract_id, contract_creator_id)
    secret_list[0]['encrypted_secret'] = enclave_keys.encrypt('a')

    secretinfo = enclave_client.verify_secrets(contract_id, contract_creator_id, secret_list)
    logger.error('failed to catch invalid secret list')
    sys.exit(-1)
except :
    pass

# -----------------------------------------------------------------
logger.info('test with long secret')
logger.info('expected error: Invalid encrypted secret')
# -----------------------------------------------------------------
try:
    secret_list = secret_helper.create_secret_list(3, enclave_keys, contract_id, contract_creator_id)
    secret_list[0]['encrypted_secret'] = enclave_keys.encrypt('abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz')

    secretinfo = enclave_client.verify_secrets(contract_id, contract_creator_id, secret_list)
    logger.error('failed to catch invalid secret list')
    sys.exit(-1)
except :
    pass

# -----------------------------------------------------------------
logger.info('test with swapped secrets')
logger.info('expected error: failed to verify the secret signature')
# -----------------------------------------------------------------
try:
    secret_list = secret_helper.create_secret_list(3, enclave_keys, contract_id, contract_creator_id)
    s = secret_list[0]['encrypted_secret']
    secret_list[0]['encrypted_secret'] = secret_list[1]['encrypted_secret']
    secret_list[1]['encrypted_secret'] = s

    secretinfo = enclave_client.verify_secrets(contract_id, contract_creator_id, secret_list)
    logger.error('failed to catch invalid secret list')
    sys.exit(-1)
except :
    pass

# -----------------------------------------------------------------
logger.info('test with invalid contract id')
logger.info('expected error: failed to verify the secret signature')
# -----------------------------------------------------------------
try:
    bad_contract_id = crypto.byte_array_to_hex(crypto.random_bit_string(256))[:32]
    secret_list = secret_helper.create_secret_list(3, enclave_keys, contract_id, contract_creator_id)

    secretinfo = enclave_client.verify_secrets(bad_contract_id, contract_creator_id, secret_list)
    logger.error('failed to catch invalid secret list')
    sys.exit(-1)
except :
    pass

# -----------------------------------------------------------------
logger.info('test with invalid creator id')
logger.info('expected error: failed to verify the secret signature')
# -----------------------------------------------------------------
try:
    bad_contract_creator_keys = keys.ServiceKeys.create_service_keys()
    bad_contract_creator_id = bad_contract_creator_keys.identity

    bad_contract_id = crypto.byte_array_to_hex(crypto.random_bit_string(256))[:32]
    secret_list = secret_helper.create_secret_list(3, enclave_keys, contract_id, contract_creator_id)

    secretinfo = enclave_client.verify_secrets(contract_id, bad_contract_creator_id, secret_list)
    logger.error('failed to catch invalid secret list')
    sys.exit(-1)
except :
    pass
