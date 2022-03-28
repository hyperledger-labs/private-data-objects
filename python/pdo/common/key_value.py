# Copyright 2022 Intel Corporation
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

import pdo.common.crypto as pcrypto
import pdo.common.utility as putils
import pdo.common.key_value_swig.key_value_swig as kvs

import logging
logger = logging.getLogger(__name__)


__block_store_initialized__ = False

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def KeyValueInitialize(block_store_file = None) :
    global __block_store_initialized__
    if __block_store_initialized__ :
        raise Exception("duplicate block store initialization")

    if block_store_file is None :
        import pdo.common.block_store_manager as pblocks
        block_store_file = pblocks.local_block_manager().block_store_file

    kvs.block_store_open(block_store_file)
    __block_store_initialized__ = True

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def KeyValueTerminate() :
    global __block_store_initialized__
    if not __block_store_initialized__ :
        return

    kvs.block_store_close()
    __block_store_initialized__ = False

import atexit
atexit.register(KeyValueTerminate)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def KeyValueGetBlock(hash_identity) :
    raw_hash_identity = pcrypto.base64_to_byte_array(hash_identity)
    return kvs.block_store_get(raw_hash_identity)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class KeyValueStore(object) :
    """
    """

    input_encoding_conversion = {
        'raw' : lambda x : x,
        'str' : pcrypto.string_to_byte_array,
        'b64' : pcrypto.base64_to_byte_array,
        'hex' : pcrypto.hex_to_byte_array,
    }

    output_encoding_conversion = {
        'raw' : lambda x : x,
        'str' : pcrypto.byte_array_to_string,
        'b64' : pcrypto.byte_array_to_base64,
        'hex' : pcrypto.byte_array_to_hex,
    }

    # -----------------------------------------------------------------
    def __init__(self, encryption_key = None, hash_identity = None) :
        """initialize the key value store

        encryption_key -- base64 encoded AES encryption key
        hash_identity -- base64 encoded hash of the root block of the kv store
        """
        if not __block_store_initialized__ :
            KeyValueInitialize()

        if encryption_key is None :
            encryption_key = pcrypto.byte_array_to_base64(pcrypto.SKENC_GenerateKey())

        self.encryption_key = encryption_key
        self.hash_identity = hash_identity
        self.__handle__ = None

    # -----------------------------------------------------------------
    @property
    def raw_hash_identity(self) :
        if self.hash_identity is None :
            return None
        return pcrypto.base64_to_byte_array(self.hash_identity)

    # -----------------------------------------------------------------
    # -----------------------------------------------------------------
    @property
    def raw_encryption_key(self) :
        return pcrypto.base64_to_byte_array(self.encryption_key)

    # -----------------------------------------------------------------
    def __enter__(self) :
        if self.__handle__ is not None :
            raise Exception("unsupported operation")

        if self.hash_identity is None :
            self.__handle__ = kvs.key_value_create(self.raw_encryption_key)
        else :
            self.__handle__ = kvs.key_value_open(self.raw_hash_identity, self.raw_encryption_key)

    # -----------------------------------------------------------------
    def __exit__(self, *args) :
        if self.__handle__ is not None :
            hash_identity = kvs.key_value_finalize(self.__handle__)
            self.hash_identity = pcrypto.byte_array_to_base64(hash_identity)
            self.__handle__ = None

    # -----------------------------------------------------------------
    def set(self, key, val, input_encoding = 'str', output_encoding = 'str') :
        if self.__handle__ :
            raise Exception("key value store not opened")

        _key = self.input_encoding_conversion[input_encoding](key)
        _val = self.input_encoding_conversion[input_encoding](val)
        _result = kvs.key_value_set(self.__handle__, _key, _val)
        return self.output_encoding_conversion[output_encoding](_result)

    # -----------------------------------------------------------------
    def get(self, key, input_encoding = 'str', output_encoding = 'str') :
        if self.__handle__ :
            raise Exception("key value store not opened")

        _key = self.input_encoding_conversion[input_encoding](key)
        _result = kvs.key_value_get(self.__handle__, _key)
        return self.output_encoding_conversion[output_encoding](_result)
