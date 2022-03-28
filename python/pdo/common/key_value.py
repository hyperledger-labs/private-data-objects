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

from array import array
import hashlib
import json
import time

import pdo.common.crypto as pcrypto
import pdo.common.utility as putils
import pdo.common.key_value_swig.key_value_swig as kvs
import pdo.common.config as pconfig

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
        block_store_file = pconfig.shared_configuration(['StorageService', 'KeyValueStore'], "./keyvalue.mdb")
        kvs.SetLogger(logger)

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
        if self.__handle__ is None :
            raise Exception("key value store not opened")

        _key = self.input_encoding_conversion[input_encoding](key)
        _val = self.input_encoding_conversion[input_encoding](val)
        _result = kvs.key_value_set(self.__handle__, _key, _val)
        return self.output_encoding_conversion[output_encoding](_result)

    # -----------------------------------------------------------------
    def get(self, key, input_encoding = 'str', output_encoding = 'str') :
        if self.__handle__ is None :
            raise Exception("key value store not opened")

        _key = self.input_encoding_conversion[input_encoding](key)
        _result = kvs.key_value_get(self.__handle__, _key)
        return self.output_encoding_conversion[output_encoding](_result)

    # --------------------------------------------------
    def __check_block__(self, block_id, input_encoding='b64') :
        """Return the metadata for a given block

        :param block_id string: block identifier
        :param input_encoding string: encoding to use for block identifiers, raw/b64
        """

        block_hash = self.input_encoding_conversion[input_encoding](block_id)

        try :
            block_meta_data = kvs.block_store_head(block_hash)
            size = block_meta_data['block_size']
            duration = block_meta_data['expiration_time'] - int(time.time())
        except ValueError :
            size = 0
            duration = 0

        result = {'size' : size, 'duration' : duration}
        return result

    # --------------------------------------------------
    def __get_block__(self, block_id, input_encoding='b64') :
        """Return the data for a block given the hash of the block

        :param block_id string: block identifier
        :param input_encoding string: encoding to use for block identifiers, raw/b64
        :return string: block data
        """

        block_hash = self.input_encoding_conversion[input_encoding](block_id)

        raw_block_data = kvs.block_store_get(block_hash)
        block_data = array('B', raw_block_data).tobytes()

        return block_data

    # -----------------------------------------------------------------
    def __get_block_iterator__(self, block_ids, input_encoding='b64') :
        """Return the data for blocks given a list of block identifiers

        :param block_ids list of string: block identifiers
        :param input_encoding string: encoding to use for block identifiers, raw/b64
        :return string: block data
        """

        for block_id in block_ids :
            block_data = self.__get_block__(block_id, input_encoding)
            if block_data is None :
                raise Exception('unable to locate required block; {}'.format(block_id))
            yield block_data

    # -----------------------------------------------------------------
    def __store_block__(self, block_data, duration=60, input_encoding='str') :
        """
        """

        block_data = self.input_encoding_conversion[input_encoding](block_data)
        block_hash = hashlib.sha256(block_data).digest()
        block_hash = pcrypto.string_to_byte_array(block_hash)

        kvs.block_store_put(block_hash, block_data)

    # -----------------------------------------------------------------
    def sync_to_block_store(self, dst_block_store, **kwargs) :
        if self.__handle__ is not None :
            raise Exception("key value store must be closed to sync")

        default_minimum_duration = pconfig.shared_configuration(['Replication', 'MinimumDuration'], 5)
        minimum_duration = kwargs.get('minimum_duration', default_minimum_duration)

        default_duration = pconfig.shared_configuration(['Replication', 'Duration'], 60)
        duration = kwargs.get('duration', default_duration)

        try :
            root_block = (self.__get_block__(self.hash_identity, input_encoding='b64'))
        except Exception :
            logger.exception('failed to get root block from local kv store')
            raise

        try :
            root_block = root_block.decode('utf8')
        except AttributeError :
            pass

        root_block = root_block.rstrip('\0')
        root_block_json = json.loads(root_block)

        block_ids = [self.hash_identity] + root_block_json['BlockIds']

        # check to see which blocks need to be pushed
        blocks_to_extend = []
        blocks_to_push = []
        block_status_list = dst_block_store.check_blocks(block_ids)

        for block_status in block_status_list :
            # if the size is 0 then the block is unknown to the storage service
            if block_status['size'] == 0 :
                blocks_to_push.append(block_status['block_id'])

            # if the expiration is nearing, then add to the list to extend, the
            # policy here is to extend if the block is within 5 seconds of expiring
            elif block_status['duration'] < minimum_duration :
                blocks_to_extend.append(block_status['block_id'])

        # there is currently no operation to simply extend the expiration of
        # an existing block, so for now just add the blocks to extend onto
        # the end of the blocks to push
        blocks_to_push += blocks_to_extend
        if len(blocks_to_push) == 0 :
            return 0

        block_data_list = self.__get_block_iterator__(blocks_to_push)
        block_store_list = dst_block_store.store_blocks(block_data_list, duration=duration)

        if block_store_list is None :
            raise Exception('failed to push blocks to block_store')

        return len(blocks_to_push)

        # -----------------------------------------------------------------
    def sync_from_block_store(self, root_block_id, src_block_store, **kwargs) :
        if self.__handle__ is not None :
            raise Exception("key value store must be closed to sync")

        default_minimum_duration = pconfig.shared_configuration(['Replication', 'MinimumDuration'], 5)
        minimum_duration = kwargs.get('minimum_duration', default_minimum_duration)

        default_duration = pconfig.shared_configuration(['Replication', 'Duration'], 60)
        duration = kwargs.get('duration', default_duration)

        try :
            root_block = src_block_store.get_block(root_block_id)
        except Exception :
            logger.exception('failed to get root block from remote kv store')
            raise

        try :
            root_block = root_block.decode('utf8')
        except AttributeError :
            pass

        root_block = root_block.rstrip('\0')
        root_block_json = json.loads(root_block)
        block_ids = [root_block_id] + root_block_json['BlockIds']

        # check to see which blocks need to be pushed
        blocks_to_extend = []
        blocks_to_pull = []
        for block_id in block_ids :
            block_status = self.__check_block__(block_id)

            # if the size is 0 then the block is unknown to the storage service
            if block_status['size'] == 0 :
                blocks_to_pull.append(block_id)

            # if the expiration is nearing, then add to the list to extend, the
            # policy here is to extend if the block is within 5 seconds of expiring
            elif block_status['duration'] < minimum_duration :
                blocks_to_extend.append(block_id)

        # there is currently no operation to simply extend the expiration of
        # an existing block, so for now just add the blocks to extend onto
        # the end of the blocks to push
        blocks_to_pull += blocks_to_extend

        if len(blocks_to_pull) == 0 :
            return 0

        block_data_list = src_block_store.get_blocks(blocks_to_pull)
        for block_data in block_data_list :
            self.__store_block__(block_data, input_encoding='raw')

        # if block_store_list is None :
        #     raise Exception('failed to push blocks to block_store')

        self.hash_identity = root_block_id
        return len(blocks_to_pull)
