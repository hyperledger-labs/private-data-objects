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

import logging
logger = logging.getLogger(__name__)

from pdo.service_client.generic import GenericServiceClient
from pdo.service_client.generic import MessageException

class ProvisioningServiceClient(GenericServiceClient) :
    """Class to wrap JSON RPC calls to the provisioning service
    """

    def __init__(self, url) :
        super().__init__(url);

        self.public_info = self.get_public_info()
        self.verifying_key = self.public_info['pspk']

    @property
    def identity(self) :
        return self.verifying_key

    # -----------------------------------------------------------------
    # enclave_id -- string containing PEM-encoded enclave public key
    # contract_id -- 256-character hex-encoded string containing the transaction ID for contract registration
    # creator_id -- string containing PEM-encoded contract owner's public key - used to verify signature
    # signature -- hex-encoded string signature of (enclave_id + contract_id) signed with owner's private key
    # -----------------------------------------------------------------
    def get_secret(self, enclave_id, contract_id, creator_id, signature) :
        request = {
            'reqType': 'secretRequest',
            'enclave_id': enclave_id,
            'contract_id': contract_id,
            'opk': creator_id,
            'signature': signature,
        }
        try :
            return self._postmsg(request)

        except MessageException as me :
            logger.warn('Provisioning service get_secret() failed: %s', me)
            return None

        except :
            logger.exception('get_secret')
            return None

    # -----------------------------------------------------------------
    def get_public_info(self) :
        request = {
            'reqType' : 'dataRequest',
        }

        try :
            return self._postmsg(request)

        except MessageException as me :
            logger.warn('Provisioning service get_public_info() failed: %s', me)
            return None

        except :
            logger.exception('get_public_info')
            return None
