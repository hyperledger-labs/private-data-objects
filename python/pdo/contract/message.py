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
import json
import os

import pdo.common.crypto as crypto
from pdo.common.utility import deprecated
from pdo.client.SchemeExpression import SchemeExpression

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class InvocationRequest(dict):
    """Invocation Request that encodes requests in the format
    specified in the interpreter inovcation documentation.
    """
    def __init__(self, method, *args, **kwargs) :
        super(InvocationRequest, self).__init__(**kwargs)

        self.__method__ = method;
        self.__positional_parameters__ = args

    def __repr__(self) :
        return self.serialize()

    def serialize(self) :
        request = dict()
        request['Method'] = self.__method__
        request['PositionalParameters'] = self.__positional_parameters__
        request['KeywordParameters'] = self
        return json.dumps(request)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class GipsyInvocationRequest(InvocationRequest) :
    """Invocation Request that encodes requests as a Scheme
    s-expression. Assumes that all strings have been fully escaped
    in the parameter lists.
    """

    @staticmethod
    def convert_sexpression(expr) :
        """conversion function for parameters that are Scheme expressions
        """
        try :
            sexpr = SchemeExpression.ParseExpression(str(expr))
            if sexpr.type == 'string' or sexpr.type == 'symbol' :
                s = str(sexpr)
                if len(s) == 0 :
                    return '""'
                elif s[0] == '"' :
                    return s
                else :
                    s = s.encode('unicode_escape').decode('utf8')
                    return f'"{s}"'
            return str(expr)
        except :
            raise RuntimeError('invalid scheme expression; {0}'.format(s))

    def __init__(self, method, *args, **kwargs) :
        super(GipsyInvocationRequest, self).__init__(method, *args, **kwargs)

    def serialize(self) :
        """construct an s-expression from positional and keyword parameters,
        the expression will have the form '(method pp1 pp2 ... (kw1 v1) (kw2 v2) ..)
        """
        pparms = ""
        for p in self.__positional_parameters__ :
            pparms += " {0}".format(GipsyInvocationRequest.convert_sexpression(p))

        kparms = ""
        for k in self.keys() :
            kp_key = GipsyInvocationRequest.convert_sexpression(k)
            kp_val = GipsyInvocationRequest.convert_sexpression(self[k])
            kparms += " ({0} {1})".format(kp_key, kp_val)

        return "'({0} {1} {2})".format(self.__method__, pparms, kparms)

# -----------------------------------------------------------------
def invocation_request(method, *args, **kwargs) :
    if os.environ.get("PDO_INTERPRETER", "gipsy") :
        return GipsyInvocationRequest(method, *args, **kwargs)

    return InvocationRequest(method, *args, **kwargs)

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
