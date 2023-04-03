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
import errno
import json

import pdo.common.crypto as crypto
import pdo.common.utility as putils

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ContractCode(object) :
    __extension__ = {
        'wawaka' : '.b64',
        'wawaka-opt' : '.b64',
    }

    # -------------------------------------------------------
    @classmethod
    def create_from_file(cls, name, source_name = None, search_path = ['.', '..', './contracts'], interpreter=None) :
        """Create a code object from a contract source file

        :param name str: the name of the contract class
        :param source_name str: the name of the source file
        :param search_path list of str: directories to search for the source file
        """
        if source_name is None :
            source_name = name
        if interpreter is None :
            interpreter = os.environ.get("PDO_INTERPRETER", "wawaka")

        basename = putils.build_simple_file_name(source_name, extension=cls.__extension__[interpreter])
        filename = putils.find_file_in_path(basename, search_path)
        logger.debug('load %s contract from %s', interpreter, filename)

        with open(filename, "r") as cfile :
            code = cfile.read()

        return cls(code, name)

    # -------------------------------------------------------
    def __init__(self, code, name, nonce = None) :
        if nonce is None :
            nonce = crypto.byte_array_to_hex(crypto.random_bit_string(16))

        self.code = code
        self.name = name
        self.nonce = nonce

    # -------------------------------------------------------
    def serialize(self, compact=False) :
        result = dict()
        if not compact :
            result['Code'] = self.code
        result['Name'] = self.name
        result['Nonce'] = self.nonce
        result['CodeHash'] = self.compute_hash(encoding='b64')

        return result

    # -------------------------------------------------------
    def compute_hash(self, encoding = 'raw') :
        # the code hash is a combination of the hash of the actual code,
        # and the hash of the nonce.
        # this makes it possible to use the nonce to verify the identity
        # of the actual code (think MRENCLAVE).
        code_hash = crypto.compute_message_hash(crypto.string_to_byte_array(self.code + self.name))
        nonce_hash = crypto.compute_message_hash(crypto.string_to_byte_array(self.nonce))
        message = code_hash + nonce_hash

        code_hash = crypto.compute_message_hash(message)
        if encoding == 'raw' :
            return code_hash
        elif encoding == 'hex' :
            return crypto.byte_array_to_hex(code_hash)
        elif encoding == 'b64' :
            return crypto.byte_array_to_base64(code_hash)
        else :
            raise ValueError('unknown hash encoding; {}'.format(encoding))

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class CompactContractCode(object) :
    """Class for storing contract code object after state initialization when
    the actual code is no longer necessary since it is stored in the contract
    state.
    """

    @classmethod
    def deserialize(cls, serialized) :
        code_hash = serialized['CodeHash']
        name = serialized['Name']
        nonce = serialized['Nonce']
        return cls(code_hash, name, nonce)

    # -------------------------------------------------------
    def __init__(self, code_hash, name, nonce) :
        self.code_hash = code_hash
        self.name = name
        self.nonce = nonce

    # -------------------------------------------------------
    def serialize(self, compact=False) :
        result = dict()
        result['Name'] = self.name
        result['Nonce'] = self.nonce
        result['CodeHash'] = self.compute_hash(encoding='b64')

        return result

    # -------------------------------------------------------
    def compute_hash(self, encoding = 'raw') :
        raw_code_hash = crypto.base64_to_byte_array(self.code_hash)
        if encoding == 'raw' :
            return raw_code_hash
        elif encoding == 'hex' :
            return crypto.byte_array_to_hex(raw_code_hash)
        elif encoding == 'b64' :
            return crypto.byte_array_to_base64(raw_code_hash)
        else :
            raise ValueError('unknown hash encoding; {}'.format(encoding))
