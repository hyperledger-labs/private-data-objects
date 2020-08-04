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

from pdo.eservice.utility import ias_client

import pdo.common.crypto as crypto
import pdo.common.utility as putils
import pdo.eservice.enclave.pdo_enclave_internal as enclave

import logging
logger = logging.getLogger(__name__)

__all__ = [
    'initialize',
    'initialize_with_configuration',
    'create_signup_info',
    'get_enclave_public_info',
    'get_enclave_service_info',
    'get_enclave_measurement',
    'get_enclave_basename',
    'get_enclave_epid_group',
    'block_store_open',
    'block_store_close',
    'verify_secrets',
    'send_to_contract',
    'shutdown'
]

verify_secrets = enclave.contract_verify_secrets
get_enclave_public_info = enclave.unseal_enclave_data
block_store_open = enclave.block_store_open
block_store_close = enclave.block_store_close

# -----------------------------------------------------------------
# -----------------------------------------------------------------
_pdo = None
_ias = None

_sig_rl_update_time = None
_sig_rl_update_period = 8*60*60 # in seconds every 8 hours

_epid_group = None

_cdi_policy = None

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def __find_enclave_library(config) :
    enclave_file_name = 'libpdo-enclave.signed.so'
    enclave_file_path = None

    if config :
        enclave_file_name = config.get('enclave_library', enclave_file_name)
        enclave_file_path = config.get('enclave_library_path', enclave_file_path)

    if enclave_file_path :
        filep = os.path.join(enclave_file_path, enclave_file_name);
        if os.path.exists(filep) :
            return filep
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

        return putils.find_file_in_path(enclave_file_name, search_path)

def __set_cdi_policy(config):
    """
    Extract the CDI policy from the enclave's config,
    and serialize it into json
    """
    global _cdi_policy

    if config and _cdi_policy is None:
        _cdi_policy = json.dumps(config['EnclavePolicy'])

    logger.debug("Enclave CDI policy: %s", _cdi_policy)

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
        _epid_group = get_enclave_epid_group()
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

    enclave.SetLogger(logger)

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

    num_of_enclaves = int(config.get('num_of_enclaves', 1))

    if not _ias:
        _ias = \
            ias_client.IasClient(
                IasServer = config['ias_url'],
                SpidApiKey = config['spid_api_key'],
                Spid = config['spid'],
                HttpsProxy = config.get('https_proxy', ""))

    if not _pdo:
        signed_enclave = __find_enclave_library(config)
        __set_cdi_policy(config)
        logger.debug("Attempting to load enclave at: %s", signed_enclave)
        _pdo = enclave.pdo_enclave_info(signed_enclave, config['spid'], _cdi_policy, num_of_enclaves)
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
    global _cdi_policy

    logger.info('shutdown enclave')

    _pdo = None
    _ias = None
    _sig_rl_update_time = None
    _epid_group = None
    _cdi_policy = None

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def send_to_contract(sealed_data, encrypted_session_key, encrypted_request) :
    """binary interface for invoking methods in the contract
    """
    result = enclave.contract_handle_contract_request(sealed_data, encrypted_session_key, encrypted_request)
    return bytes(result)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def send_to_contract_encoded(sealed_data, encrypted_session_key, encrypted_request) :
    """base64 interface for invoking methods in the contract
    """
    result = enclave.contract_handle_contract_encoded_request(sealed_data, encrypted_session_key, encrypted_request)
    return result

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def get_enclave_service_info(spid, config=None) :
    """Retrieve information about the enclave. This function should
    only be called outside of the normal initialization of the enclave
    and corresponding libraries.
    """
    global _pdo
    global logger

    if _pdo :
        raise Exception('get_enclave_service_info must be called exclusively')

    enclave.SetLogger(logger)

    # set the policy based on the configuration
    __set_cdi_policy(config)

    signed_enclave = __find_enclave_library(None)
    logger.debug("Attempting to load enclave at: %s", signed_enclave)

    num_of_enclaves = 1
    pdo = enclave.pdo_enclave_info(signed_enclave, spid, _cdi_policy, num_of_enclaves)
    if pdo is None :
        raise Exception('unable to load the enclave')

    info = [ pdo.mr_enclave, pdo.basename ]
    pdo = None

    return info

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
def get_enclave_epid_group():
     global _epid_group

     if _epid_group is None :
         _epid_group = _pdo.get_epid_group()

     return _epid_group

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def create_signup_info(originator_public_key_hash, nonce):
    # Part of what is returned with the signup data is an enclave quote, we
    # want to update the revocation list first.
    update_sig_rl()

    # Now, let the enclave create the signup data
    signup_data = enclave.create_enclave_data(originator_public_key_hash)
    if signup_data is None:
        return None

    # We don't really have any reason to call back down into the enclave
    # as we have everything we now need.  For other objects such as wait
    # timer and certificate they are serialized into JSON down in C++ code.
    #
    # Start building up the signup info dictionary we will serialize
    signup_info = {
        'interpreter' : signup_data['interpreter'],
        'verifying_key': signup_data['verifying_key'],
        'encryption_key': signup_data['encryption_key'],
        'proof_data': 'Not present',
        'enclave_persistent_id': 'Not present'
    }

    # If we are not running in the simulator, we are going to go and get
    # an attestation verification report for our signup data.
    if not enclave.is_sgx_simulator():
        logger.debug("posting verification to IAS")
        response = _ias.post_verify_attestation(quote=signup_data['enclave_quote'], nonce=nonce)
        logger.debug("posted verification to IAS")

        #check verification report
        if not _ias.verify_report_fields(signup_data['enclave_quote'], response['verification_report']):
            logger.debug("last error: " + _ias.last_verification_error())
            if _ias.last_verification_error() == "GROUP_OUT_OF_DATE":
                logger.warning("failure GROUP_OUT_OF_DATE (update your BIOS/microcode!!!) keep going")
            else:
                logger.error("invalid report fields")
                return None
        #ALL checks have passed
        logger.info("report fields verified")

        # Now put the proof data into the dictionary
        signup_info['proof_data'] = \
            json.dumps({
                'verification_report': response['verification_report'],
                'certificates': response['ias_certificates'], # Note: this is a list with certification path, signer first
                'signature': response['ias_signature']
            })

        # Grab the EPID psuedonym and put it in the enclave-persistent ID for the
        # signup info
        verification_report_dict = json.loads(response['verification_report'])
        signup_info['enclave_persistent_id'] = verification_report_dict.get('epidPseudonym')

    # Now we can finally serialize the signup info and create a corresponding
    # signup info object.  Because we don't want the sealed signup data in the
    # serialized version, we set it separately.

    signup_info_obj = enclave.deserialize_signup_info(json.dumps(signup_info))
    signup_info_obj.sealed_signup_data = signup_data['sealed_enclave_data']

    # Now we can return the real object
    return signup_info_obj
