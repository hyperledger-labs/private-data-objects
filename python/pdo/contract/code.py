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
    # -------------------------------------------------------
    @classmethod
    def create_from_scheme_file(cls, name, source_name = None, search_path = ['.', '..', './contracts']) :
        """Create a code object from a Gipsy source file

        :param name str: the name of the scheme contract class
        :param source_name str: the name of the source file
        :param search_path list of str: directories to search for the source file
        """
        if source_name is None :
            source_name = name
        gipsy_enabled = os.environ.get('GIPSY_ENABLED')
       
        if gipsy_enabled == 'false' :
            basename =  putils.build_file_name(source_name, extension='.txt')
        else :
            basename = putils.build_file_name(source_name, extension='.scm')

        filename = putils.find_file_in_path(basename, search_path)
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
    def serialize(self) :
        result = dict()
        result['Code'] = self.code
        result['Name'] = self.name
        result['Nonce'] = self.nonce

        return result

    # -------------------------------------------------------
    def __serialize_for_hashing(self) :
        return self.code + self.name + self.nonce

    # -------------------------------------------------------
    def compute_hash(self, encoding = 'raw') :
        serialized = self.__serialize_for_hashing()
        code_hash = crypto.compute_message_hash(crypto.string_to_byte_array(serialized))
        if encoding == 'raw' :
            return code_hash
        elif encoding == 'hex' :
            return crypto.byte_array_to_hex(code_hash)
        elif encoding == 'b64' :
            return crypto.byte_array_to_base64(code_hash)
        else :
            raise ValueError('unknown hash encoding; {}'.format(encoding))
