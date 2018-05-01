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

import random
import pdo.common.crypto as crypto
import pdo.common.keys as keys

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class Secret(object) :
    # encoded_secret -- hex encoded 128 bit string
    # enclave_id -- enclave verifying key
    # contract_id -- 16 character, hex encoded, sha256 hashed, registration transaction signature
    # creator_id -- base64 encoded, sha256 hashed, creator verifying key
    @staticmethod
    def serialize_for_signing(encoded_secret, enclave_id, contract_id, creator_id) :
        return encoded_secret + enclave_id + contract_id + creator_id

    # encoded_secret -- hex encoded 128 bit string
    # service_keys -- ServiceKeys for the provisioning service
    # enclave_keys -- EnclaveKeys for the enclave
    # contract_id -- 16 character, hex encoded, sha256 hashed, registration transaction signature
    # creator_id -- base64 encoded, sha256 hashed, creator verifying key
    def __init__(self, enclave_id, pservice_id, encoded_encrypted_secret) :
        self.EnclaveID = enclave_id
        self.PSPK = pservice_id
        self.EncryptedSecret = encoded_encrypted_secret

    @property
    def Encoded(self) :
        return { 'pspk' : self.PSPK, 'encrypted_secret' : self.EncryptedSecret }


# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ProvisioningService(object) :
    """A class to mimic provisioning service interfaces for local
    operation. This simplifies testing.
    """

    def __init__(self) :
        self.service_keys = keys.ServiceKeys.create_service_keys()

    @property
    def verifying_key(self) :
        return self.service_keys.verifying_key

    @property
    def identity(self) :
        return self.service_keys.verifying_key

    def get_secret(self, enclave_keys, contract_id, creator_id) :
        hex_encoded_secret = '{0:032X}'.format(random.getrandbits(128))

        message = Secret.serialize_for_signing(hex_encoded_secret, enclave_keys.identity, contract_id, creator_id)
        signature = self.service_keys.sign(message, encoding='hex')
        # must pad the signature for now...
        required_padding = 2 * crypto.MAX_SIG_SIZE - len(signature)
        signature = signature + ('0' * required_padding)

        encoded_encrypted_secret = enclave_keys.encrypt(hex_encoded_secret + signature, encoding='b64')

        return Secret(enclave_keys.identity, self.identity, encoded_encrypted_secret)


# -----------------------------------------------------------------
# -----------------------------------------------------------------
def create_secrets_for_services(ps_services, enclave_keys, contract_id, creator_id) :
    # create a secret for each of the provisioning services
    # and have it signed
    secret_list = []
    for service in ps_services :
        secret = service.get_secret(enclave_keys, contract_id, creator_id)
        secret_list.append(secret.Encoded)

    return secret_list

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def create_provisioning_services(secret_count) :
    # create keys for each of the provisioning services
    services = []
    for k in range(secret_count) :
        services.append(ProvisioningService())

    return services

# -----------------------------------------------------------------
# create_secret_list -- simulate the creation of secrets from a list
# of provisioning services without any provisioning services
#
# secret_count -- number of secrets to create
# -----------------------------------------------------------------
def create_secret_list(secret_count, enclave_keys, contract_id, creator_id) :
    ps_services = create_provisioning_services(secret_count)
    return create_secrets_for_services(ps_services, enclave_keys, contract_id, creator_id)
