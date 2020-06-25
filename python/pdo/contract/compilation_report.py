# Copyright 2020 Intel Corporation
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
from base64 import b64decode
import os

import pdo.common.crypto as crypto
import pdo.common.utility as putils

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ContractCompilationReport(object) :

     # -------------------------------------------------------
    @classmethod
    def create_from_file(cls, report_name, search_path = ['.', '..', './contracts']) :
        """Create a code object from a wawaka-aot source file

        :param report_name str: the name of the compilation report file
        :param search_path list of str: directories to search for the source file
        """
        if report_name.endswith('.b64'):
            # we may get the full file path for the contract as the report name
            # so drop the extension, so we actually find and load the report file
            report_name = os.path.basename(report_name) # only works on Linux
            report_name = report_name[:-4]
        basename = putils.build_simple_file_name(report_name, extension='.cdi')
        filename = putils.find_file_in_path(basename, search_path)
        logger.debug('load wawaka-aot compilation report from %s', filename)
        # file is json-encoded
        with open(filename, "r") as rfile :
            contents = rfile.read()
        contents = contents.rstrip('\0')
        report = json.loads(contents)

        logger.debug('loaded report %s', json.dumps(report))

        return cls.init_from_dict(report)

    @classmethod
    def init_from_dict(cls, report_dict):
        return cls(report_dict['CompilerName'], report_dict['CompilerVersion'], report_dict['CompilerConfiguration'], report_dict['SourceHash'], report_dict['BinaryHash'], report_dict['CompilerVerifyingKey'], report_dict['CompilerSignature'])

    # -------------------------------------------------------
    def __init__(self, name, version, configuration, source_hash, binary_hash, compiler_verifying_key=None, signature=None) :

        self.name = name
        self.version = version
        self.configuration = configuration
        self.source_hash = source_hash
        self.binary_hash = binary_hash
        self.compiler_verifying_key = compiler_verifying_key
        self.signature = signature

    # -------------------------------------------------------
    def serialize(self) :
        result = dict()
        result['CompilerName'] = self.name
        result['CompilerVersion'] = self.version
        result['CompilerConfiguration'] = self.configuration
        result['SourceHash'] = self.source_hash
        result['BinaryHash'] = self.binary_hash
        result['CompilerVerifyingKey'] = self.compiler_verifying_key
        result['CompilerSignature'] = self.signature
        return result

    # -------------------------------------------------------
    def __serialize_for_hashing(self) :
        serialized_compiler_inputs = self.name + self.version + self.configuration
        serialized = bytearray(serialized_compiler_inputs, encoding='utf-8')
        serialized.extend(b64decode(self.source_hash))
        serialized.extend(b64decode(self.binary_hash))
        serialized.extend(self.compiler_verifying_key.encode('utf-8'))
        serialized.extend(b64decode(self.signature))
        return serialized

    # -------------------------------------------------------
    def compute_hash(self):
        serialized = self.__serialize_for_hashing()
        report_hash = crypto.compute_message_hash(serialized)
        # the contract code class expects a string when serializing
        # for hashing, so use Base64 encoding
        return crypto.byte_array_to_base64(report_hash)
