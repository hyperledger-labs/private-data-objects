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

import pdo.common.crypto as crypto
from pdo.contract.invocation import InvocationRequest

from pdo.common.utility import deprecated

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ContractMessage(object) :
    def __init__(self, request_originator_keys, channel_id, **kwargs) :
        """
        :param request_originator_keys: object of type ServiceKeys
        :param channel_id: nonce
        """
        self.__request_originator_keys = request_originator_keys
        self.channel_id = channel_id

        # remove this when we are convinced that we've converted
        # all forms to use InvocationRequest
        invocation_request = kwargs.get('invocation_request')
        if invocation_request :
            if not issubclass(type(invocation_request), InvocationRequest) :
                logger.warn("not an InvocationRequest: %s", str(invocation_request))

        self.invocation_request = str(kwargs.get('invocation_request', ''));

        # remove this when we are convinced that we've removed
        # all forms expressing the message through 'expression'
        assert kwargs.get('expression') is None

        self.nonce = crypto.byte_array_to_hex(crypto.random_bit_string(16))

    # -------------------------------------------------------
    @property
    @deprecated
    def expression(self) :
        return self.invocation_request

    # -------------------------------------------------------
    @property
    def originator_verifying_key(self) :
        return self.__request_originator_keys.identity

    def serialize_for_signing(self) :
        return self.invocation_request + self.channel_id + self.nonce

    # -------------------------------------------------------
    def serialize_for_hash(self) :
        return self.invocation_request + self.nonce

    # -------------------------------------------------------
    @property
    def signature(self) :
        return self.__request_originator_keys.sign(self.serialize_for_signing(), encoding='b64')

    # -------------------------------------------------------
    def compute_hash(self) :
        return crypto.compute_message_hash(crypto.string_to_byte_array(self.serialize_for_hash()))

    # -------------------------------------------------------
    def serialize(self) :
        result = dict()
        result['InvocationRequest'] = self.invocation_request
        result['OriginatorVerifyingKey'] = self.originator_verifying_key
        result['ChannelVerifyingKey'] = self.channel_id
        result['Nonce'] = self.nonce
        result['Signature'] = self.signature

        return result
