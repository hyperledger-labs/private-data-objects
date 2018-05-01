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

import pdo.common.crypto as crypto

import logging
logger = logging.getLogger(__name__)

__all__ = ['serialize_for_signing', 'verify_state_encryption_key_signature']

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def serialize_for_signing(encrypted_state_key, secret_list, contract_id, creator_id) :
    """Create a buffer with the canonical serialization of secret list
    for verifying the signature from the enclave

    :param string encrypted_state_key: base64 encoded string
    :param array of dictionaries secret_list: dictionary defines values for pspk and encrypted_secret
    :param string contract_id: 16 character, hex encoded, sha256 hashed, registration transaction signature
    :param string creator_id: PEM encoded ECDSA verifying key
    """
    message = crypto.string_to_byte_array(contract_id)
    message += crypto.string_to_byte_array(creator_id)

    for secret in secret_list :
        message += crypto.string_to_byte_array(secret['pspk'])
        message += crypto.string_to_byte_array(secret['encrypted_secret'])

    message += crypto.base64_to_byte_array(encrypted_state_key)
    return message

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def verify_state_encryption_key_signature(
        encrypted_state_key,
        secret_list,
        contract_id,
        creator_id,
        signature,
        enclave_keys) :
    """verify the signature on the contract state encryption key received from the enclave

    :param encrypted_state_key; base64 encoded string
    :param secret_list: array of dictionary defines values for pspk and encrypted_secret
    :param contract_id: 16 character, hex encoded, sha256 hashed, registration transaction signature
    :param creator_id: PEM encoded ECDSA verifying key
    :param signature: base64 encoded signature
    :param enclave_keys: object of type :EnclaveKeys:
    """
    message = serialize_for_signing(encrypted_state_key, secret_list, contract_id, creator_id)
    logger.debug("signed message has length %d and hash %s",
                 len(message),
                 crypto.byte_array_to_base64(crypto.compute_message_hash(message)))

    return enclave_keys.verify(message, signature, encoding='b64')
