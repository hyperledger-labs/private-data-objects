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
from pdo.common.utility import deprecated

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ContractMessage(object) :
    def __init__(self, request_originator_keys, channel_keys, **kwargs) :
        """
        :param request_originator_keys: object of type ServiceKeys
        :param channel_keys: object of type TransactionKeys
        """
        self.__request_originator_keys = request_originator_keys
        self.__channel_keys = channel_keys

        self.invocation_request = kwargs.get('invocation_request', '');
        if kwargs.get('expression') :
            logger.warn('deprecated use of expression parameter')
            self.invocation_request = kwargs.get('expression', '')

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

    # -------------------------------------------------------
    @property
    def channel_verifying_key(self) :
        return self.__channel_keys.txn_public

    # -------------------------------------------------------
    def serialize_for_signing(self) :
        return self.invocation_request + self.channel_verifying_key + self.nonce

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
        result['ChannelVerifyingKey'] = self.channel_verifying_key
        result['Nonce'] = self.nonce
        result['Signature'] = self.signature

        return result
