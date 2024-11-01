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

"""helper.py

This file defines a class to implement the various storage service
operations on the lmdb file.
"""

import base64
import hashlib
import lmdb
import struct
import time
import json

import pdo.common.config as pconfig
from pdo.service_client.storage import StorageException

import logging
logger = logging.getLogger(__name__)

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
import threading
__block_manager_lock__ = threading.Lock()
__local_block_manager__ = None

def local_block_manager() :
    global __local_block_manager__

    __block_manager_lock__.acquire()
    if __local_block_manager__ is None :
        block_store_file = pconfig.shared_configuration(['StorageService','BlockStore'], "./blockstore.mdb")

        __local_block_manager__ = BlockStoreManager(block_store_file, True)
    __block_manager_lock__.release()

    return __local_block_manager__

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class BlockMetadata(object) :
    """Implements a wrapper for block metadata.
    """

    minimum_duration_time = 60

    @classmethod
    def unpack(cls, value) :
        metadata = struct.unpack('LLLL', value)

        obj = cls()
        obj.block_size = metadata[0]
        obj.create_time = metadata[1]
        obj.expiration_time = metadata[2]
        obj.mark = metadata[3]

        return obj

    def __init__(self) :
        self.block_size = 0
        self.create_time = 0
        self.expiration_time = 0
        self.mark = 0

    def pack(self) :
        value = struct.pack('LLLL', self.block_size, self.create_time, self.expiration_time, self.mark)
        return value

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class BlockStoreManager(object) :
    """Implements the storage service operations in a way that provides
    symmetry with the storage service client.
    """

    map_size = 1 << 40

    # --------------------------------------------------
    def __init__(self, block_store_file, create_block_store=False) :
        """Initialize storage service class instance

        :param block_store_file string: name of the lmdb file used for block storage
        :param service_keys ServiceKeys: ECDSA keys used to sign storage contracts
        :param create_block_store boolean: flag to note that missing blockstore file should be created
        """
        self.block_store_file = block_store_file
        self.block_store_env = lmdb.open(
            block_store_file,
            create=create_block_store,
            max_dbs=2,
            subdir=False,
            sync=False,
            map_size=self.map_size)

    # --------------------------------------------------
    def close(self) :
        """Sync the database to disk and close the handles
        """
        self.block_store_env.sync()
        self.block_store_env.close()
        self.block_store_env = None

    # --------------------------------------------------
    def list_blocks(self, encoding='b64') :
        """Return a list of all block identifiers currently
        stored in the database; mostly for debugging purposes

        :param encoding string: encoding to use for block identifiers, raw/b64
        :return list of string: list of block identifiers
        """
        encoding_fn = lambda x : x
        if encoding == 'b64' :
            encoding_fn = lambda x : base64.urlsafe_b64encode(x).decode()

        mdb = self.block_store_env.open_db(b'meta_data')

        block_ids = []
        with self.block_store_env.begin() as txn :
            cursor = txn.cursor(db=mdb)
            for key, value in cursor :
                block_ids.append(encoding_fn(key))

        return block_ids

    # --------------------------------------------------
    def __get_block__(self, block_id, encoding='b64') :
        """Return the data for a block given the hash of the block

        :param block_id string: block identifier
        :param encoding string: encoding to use for block identifiers, raw/b64
        :return string: block data
        """
        decoding_fn = lambda x : x
        if encoding == 'b64' :
            decoding_fn = lambda x : base64.urlsafe_b64decode(x)

        block_hash = decoding_fn(block_id)
        bdb = self.block_store_env.open_db(b'block_data')
        with self.block_store_env.begin() as txn :
            block_data = txn.get(block_hash, db=bdb)

        return block_data

    # --------------------------------------------------
    def __block_iterator__(self, block_ids, encoding) :
        """Create an iterator that is more memory efficient because it
        only reads the block when necessary

        :param block_ids list of string: block identifiers
        :param encoding string: encoding to use for block identifiers, raw/b64
        """

        for block_id in block_ids :
            block_data = self.__get_block__(block_id, encoding)
            if block_data is None :
                raise Exception('unable to locate required block; {}'.format(block_id))
            yield block_data

    # --------------------------------------------------
    def get_block(self, block_id, encoding='b64') :
        return self.__get_block__(block_id, encoding)

    # --------------------------------------------------
    def get_blocks(self, block_ids, encoding='b64') :
        """Return the data for a list of blocks

        :param block_ids list of string: block identifiers
        :param encoding string: encoding to use for block identifiers, raw/b64
        :return iterable: list of block data
        """

        # the iterator means that we don't have to use as much memory
        # for operations that can process the blocks one at a time
        return self.__block_iterator__(block_ids, encoding)

    # --------------------------------------------------
    def store_block(self, block_data, duration=60, encoding='b64') :
        """Add a new data block to the store

        :param block_data string: binary content of the block
        :param encoding string: encoding to use for block identifiers, raw/b64
        :return string: block identifier
        """
        return self.store_blocks([block_data], duration, encoding)

    # --------------------------------------------------
    def store_blocks(self, block_data_list, duration=60, encoding='b64') :
        """Save a list of blocks in the store

        :param iterable block_data_list: iterable collection of blocks to store
        :param duration int: number of seconds to store data
        :param encoding string: encoding to use for block identifiers, raw/b64
        :return list of string: list of block identifiers
        """

        if duration < BlockMetadata.minimum_duration_time :
            duration = BlockMetadata.minimum_duration_time

        encoding_fn = lambda x : x
        if encoding == 'b64' :
            encoding_fn = lambda x : base64.urlsafe_b64encode(x).decode()

        current_time = int(time.time())
        expiration_time = current_time + duration

        mdb = self.block_store_env.open_db(b'meta_data')
        bdb = self.block_store_env.open_db(b'block_data')

        block_hashes = []

        # this might keep the database locked for too long for a write transaction
        # might want to flip the order, one transaction per update
        with self.block_store_env.begin(write=True) as txn :
            for block_data in block_data_list :
                block_hash = hashlib.sha256(block_data).digest()
                block_hashes.append(block_hash)

                # need to check to see if the block already exists, if it
                # does then just extend the expiration time if necessary
                raw_metadata = txn.get(block_hash, db=mdb)
                if raw_metadata :
                    metadata = BlockMetadata.unpack(raw_metadata)
                    if expiration_time > metadata.expiration_time :
                        metadata.expiration_time = expiration_time
                        if not txn.put(block_hash, metadata.pack(), db=mdb, overwrite=True) :
                            raise StorageException("failed to update metadata")

                    continue

                # this is a new block that needs to be added
                metadata = BlockMetadata()
                metadata.block_size = len(block_data)
                metadata.create_time = current_time
                metadata.expiration_time = expiration_time
                metadata.mark = 0

                if not txn.put(block_hash, metadata.pack(), db=mdb) :
                    raise StorageException("failed to save metadata")

                if not txn.put(block_hash, block_data, db=bdb) :
                    raise StorageException("failed to save block data")

        return block_hashes

    # --------------------------------------------------
    def check_block(self, block_id, encoding='b64') :
        return self.check_blocks([block_id], encoding)

    # --------------------------------------------------
    def check_blocks(self, block_ids, encoding='b64') :
        """Check status of a list of block

        :param block_ids list of string: block identifiers
        :param encoding string: encoding to use for block identifiers, raw/b64
        :return list of dict: list of block status
        """

        decoding_fn = lambda x : x
        if encoding == 'b64' :
            decoding_fn = lambda x : base64.urlsafe_b64decode(x)

        current_time = int(time.time())
        mdb = self.block_store_env.open_db(b'meta_data')

        block_status_list = []
        with self.block_store_env.begin() as txn :
            for block_id in block_ids :
                # use the input format for the output block identifier
                block_status = { 'block_id' : block_id, 'size' : 0, 'duration' : 0 }
                block_hash = decoding_fn(block_id)

                raw_metadata = txn.get(block_hash, db=mdb)
                if raw_metadata :
                    metadata = BlockMetadata.unpack(raw_metadata)
                    block_status['size'] = metadata.block_size
                    block_status['duration'] = metadata.expiration_time - current_time
                    if block_status['duration'] < 0 :
                        block_status['duration'] = 0

                block_status_list.append(block_status)

        return block_status_list

    # --------------------------------------------------
    def expire_blocks(self) :
        """Delete data and metadata for blocks that have expired
        """
        try :
            mdb = self.block_store_env.open_db(b'meta_data')
            bdb = self.block_store_env.open_db(b'block_data')

            current_time = int(time.time())

            count = 0
            with self.block_store_env.begin() as txn :
                cursor = txn.cursor(db=mdb)
                for key, value in cursor :
                    metadata = BlockMetadata.unpack(value)
                    if metadata.expiration_time < current_time :
                        count += 1
                        with self.block_store_env.begin(write=True) as dtxn :
                            assert dtxn.delete(key, db=bdb)
                            assert dtxn.delete(key, db=mdb)

            logger.info('expired %d blocks', count)
        except Exception as e :
            logger.error('garbage collection failed; %s', str(e))
            return None

        return count

# --------------------------------------------------
def decode_root_block(root_block) :
    """decode the raw root block and parse the JSON
    """

    if root_block is None :
        raise StorageException("invalid root block")

    # backward compatibility with json parser
    try :
        root_block = root_block.decode('utf8')
    except AttributeError :
        pass

    try :
        root_block = root_block.rstrip('\0')
        root_data = json.loads(root_block)
    except json.JSONDecodeError :
        raise StorageException("invalid root block")

    return root_data

# --------------------------------------------------
def sync_block_store(src_block_store, dst_block_store, root_block_id, root_block = None, **kwargs) :
    """
    ensure that required blocks are stored in the storage service

    assumes that all of the blocks referenced by root_block_id are in the source
    block manager

    :param src_block_store object implementing the block_store_manager interface
    :param dst_block_store object implementing the block_store_manager interface
    :param root_block_id string: block identifier for the root block
    :param root_block string: block data for the root block
    """
    if root_block is None :
        root_block = src_block_store.get_block(root_block_id)

    block_ids = [root_block_id]

    try :
        root_block = root_block.decode('utf8')
    except AttributeError :
        pass

    root_block = root_block.rstrip('\0')
    root_block_json = json.loads(root_block)
    block_ids.extend(root_block_json['BlockIds'])

    default_minimum_duration = pconfig.shared_configuration(['Replication', 'MinimumDuration'], 5)
    minimum_duration = kwargs.get('minimum_duration', default_minimum_duration)

    default_duration = pconfig.shared_configuration(['Replication', 'Duration'], 60)
    duration = kwargs.get('duration', default_duration)

    # check to see which blocks need to be pushed
    blocks_to_push = []
    blocks_to_extend = []
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

    block_data_list = src_block_store.get_blocks(blocks_to_push)
    block_store_list = dst_block_store.store_blocks(block_data_list, duration=duration)
    if block_store_list is None :
        raise Exception('failed to push blocks to block_store')

    return len(blocks_to_push)
