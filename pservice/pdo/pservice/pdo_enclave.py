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
import time
import toml

from ssl import SSLError
from requests.exceptions import Timeout
from requests.exceptions import HTTPError

from pdo.pservice.utility import ias_client

import pdo.common.crypto as crypto
import pdo.pservice.enclave.pdo_enclave_internal as enclave

import logging
logger = logging.getLogger(__name__)

__all__ = [
    'initialize',
    'initialize_with_configuration',
    'create_enclave_info',
    'get_enclave_public_info',
    'get_enclave_measurement',
    'get_enclave_basename',
    'create_secret',
    'unseal_secret',
    'generate_enclave_secret',
    'shutdown'
]


get_enclave_public_info = enclave.unseal_enclave_data

# -----------------------------------------------------------------
# -----------------------------------------------------------------
_pdo = None
_ias = None

_sig_rl_update_time = None
_sig_rl_update_period = 8*60*60 # in seconds every 8 hours

_epid_group = None

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def __find_enclave_library(config) :
    enclave_file_name = config.get('enclave_library', 'libpdo-enclave.signed.so')
    enclave_file_path = config.get('enclave_library_path')

    if enclave_file_path :
        enclave_file = os.path.join(enclave_file_path, enclave_file_name);
        if os.path.exists(enclave_file) :
            return enclave_file
    else :
        script_directory = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
        search_path = [
            script_directory,
            os.path.abspath(os.path.join(script_directory, '..')),
            os.path.abspath(os.path.join(script_directory, '..', 'lib')),
            os.path.abspath(os.path.join(script_directory, '..', '..')),
            os.path.abspath(os.path.join(script_directory, '..', '..', 'lib')),
            os.path.abspath(os.path.join('/usr', 'lib'))
        ]

        for path in search_path :
            enclave_file = os.path.join(path, enclave_file_name)
            if os.path.exists(enclave_file) :
                return enclave_file

    raise IOError("Could not find enclave shared object")

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def update_sig_rl():
    """
    Update the revocation list
    """
    global _epid_group
    global _sig_rl_update_time
    global _sig_rl_update_period

    if _epid_group is None:
        _epid_group = _pdo.get_epid_group()
    logger.info("EPID: " + _epid_group)

    if not _sig_rl_update_time \
        or (time.time() - _sig_rl_update_time) > _sig_rl_update_period:

        sig_rl = ""
        if (not enclave.is_sgx_simulator()):
            sig_rl = _ias.get_signature_revocation_lists(_epid_group)
            logger.debug("Received SigRl of {} bytes ".format(len(sig_rl)))

        _pdo.set_signature_revocation_list(sig_rl)
        _sig_rl_update_time = time.time()


# -----------------------------------------------------------------
# -----------------------------------------------------------------
def initialize(config_dir):
    config_file = os.path.join(config_dir, 'pdo_enclave_sgx.toml')
    logger.info('Loading PDO enclave config from: %s', config_file)

    # Lack of a config file is a fatal error, so let the
    # exception percolate up to caller
    with open(config_file) as fd:
        config = toml.loads(fd.read())

    initialize_with_configuration(config)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def initialize_with_configuration(config) :
    global _pdo
    global _ias
    global logger

    enclave._SetLogger(logger)

    # Ensure that the required keys are in the configuration
    valid_keys = set(['spid', 'ias_url', 'spid_api_key'])
    found_keys = set(config.keys())

    missing_keys = valid_keys.difference(found_keys)
    if missing_keys:
        raise \
            ValueError(
                'PDO enclave config file missing the following keys: '
                '{}'.format(
                    ', '.join(sorted(list(missing_keys)))))

    if not _ias:
        _ias = \
            ias_client.IasClient(
                IasServer = config['ias_url'],
                SpidApiKey = config['spid_api_key'],
                Spid = config['spid'],
                HttpsProxy = config.get('https_proxy', ""))

    if not _pdo:
        signed_enclave = __find_enclave_library(config)
        logger.debug("Attempting to load enclave at: %s", signed_enclave)
        _pdo = enclave.pdo_enclave_info(signed_enclave, config['spid'])
        logger.info("Basename: %s", get_enclave_basename())
        logger.info("MRENCLAVE: %s", get_enclave_measurement())

    sig_rl_updated = False
    while not sig_rl_updated:
        try:
            update_sig_rl()
            sig_rl_updated = True
        except (SSLError, Timeout, HTTPError) as e:
            logger.warning("Failed to retrieve initial sig rl from IAS: %s", str(e))
            logger.warning("Retrying in 60 sec")
            time.sleep(60)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def shutdown():
    global _pdo
    global _ias
    global _sig_rl_update_time
    global _epid_group

    _pdo = None
    _ias = None
    _sig_rl_update_time = None
    _epid_group = None

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def get_enclave_measurement():
    global _pdo
    return _pdo.mr_enclave if _pdo is not None else None

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def get_enclave_basename():
    global _pdo
    return _pdo.basename if _pdo is not None else None

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def create_secret(len): return enclave.create_sealed_secret(len)


# -----------------------------------------------------------------
# -----------------------------------------------------------------
def unseal_secret(secret): return enclave.unseal_secret(secret)


# -----------------------------------------------------------------
# -----------------------------------------------------------------
def generate_enclave_secret(enclave_sealed_data, sealed_secret, contract_id, opk, enclave_info):
 return enclave.generate_enclave_secret(enclave_sealed_data, sealed_secret, contract_id, opk, enclave_info)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def create_enclave_info(nonce):
    # Part of what is returned with the enclave data is an enclave quote, we
    # want to update the revocation list first.
    update_sig_rl()

    # Now, let the enclave create the enclave data
    enclave_data = enclave.create_enclave_data()
    if enclave_data is None:
        return None

    # We don't really have any reason to call back down into the enclave
    # as we have everything we now need.  For other objects such as wait
    # timer and certificate they are serialized into JSON down in C++ code.
    #
    # Start building up the enclave info dictionary we will serialize
    enclave_info = {
        'verifying_key': enclave_data['verifying_key'],
        'encryption_key': enclave_data['encryption_key'],
        'proof_data': 'Not present',
        'enclave_persistent_id': 'Not present'
    }


    # Now we can finally serialize the enclave info and create a corresponding
    # enclave info object.  Because we don't want the sealed enclave data in the
    # serialized version, we set it separately.

    enclave_info_obj = enclave.deserialize_enclave_info(json.dumps(enclave_info))
    enclave_info_obj.sealed_enclave_data = enclave_data['sealed_enclave_data']

    # Now we can return the real object
    return enclave_info_obj
