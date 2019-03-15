# Copyright 2019 Intel Corporation
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

import pdo.common.keys as keys
from pdo.service_client.storage import StorageException

import logging
logger = logging.getLogger(__name__)

class BlockMetadata(object) :
    """Implements a wrapper for block metadata.
    """

    minimum_expiration_time = 60

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

class BlockStoreManager(object) :
    """Implements the storage service operations in a way that provides
    symmetry with the storage service client.
    """

    map_size = 1 << 40

    def __init__(self, block_store_file, service_keys = None, create_block_store=False) :
        """Initialize storage service class instance

        :param block_store_file string: name of the lmdb file used for block storage
        :param service_keys ServiceKeys: ECDSA keys used to sign storage contracts
        :param create_block_store boolean: flag to note that missing blockstore file should be created
        """
        self.service_keys = service_keys
        if self.service_keys is None :
            self.service_keys = keys.ServiceKeys.create_service_keys()

        self.block_store_env = lmdb.open(
            block_store_file,
            create=create_block_store,
            max_dbs=2,
            subdir=False,
            sync=False,
            map_size=self.map_size)

    def close(self) :
        """Sync the database to disk and close the handles
        """
        self.block_store_env.sync()
        self.block_store_env.close()
        self.block_store_env = None

    def get_service_info(self) :
        """Return useful information about the service

        :return dict: dictionary of information about the storage service
        """
        return {'verifying_key' : self.service_keys.verifying_key }

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

    def get_block(self, block_id, encoding='b64') :
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

    # return block_data_list
    def __block_iterator__(self, block_ids, encoding) :
        for block_id in block_ids :
            yield self.get_block(block_id, encoding)

    def get_blocks(self, block_ids, encoding='b64') :
        """Return the data for a list of blocks
        """
        # the iterator means that we don't have to use as much memory
        # for operations that can process the blocks one at a time
        return self.__block_iterator__(block_ids, encoding)

    def store_block(self, block_data, expiration=60, encoding='b64') :
        """Add a new data block to the store

        :param block_data string: binary content of the block
        :param encoding string: encoding to use for block identifiers, raw/b64
        :return string: block identifier
        """
        return self.store_blocks([block_data], expiration, encoding)

    def store_blocks(self, block_data_list, expiration=60, encoding='b64') :
        """Save a list of blocks in the store

        :param iterable block_data_list: iterable collection of blocks to store
        :param expiration int: number of seconds to use for expiration
        :param encoding string: encoding to use for block identifiers, raw/b64
        :return list of string: list of block identifiers
        """

        encoding_fn = lambda x : x
        if encoding == 'b64' :
            encoding_fn = lambda x : base64.urlsafe_b64encode(x).decode()

        current_time = int(time.time())
        expiration_time = current_time + expiration

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

        try :
            # going to just concatenate all hashes, safe since these are all fixed size
            signing_hash_accumulator = expiration.to_bytes(32, byteorder='big', signed=False)
            signing_hash_accumulator += b''.join(block_hashes)

            signing_hash = hashlib.sha256(signing_hash_accumulator).digest()
            signature = self.service_keys.sign(signing_hash, encoding=encoding)
        except Exception as e :
            logger.error("unknown exception packing response (BlockStatus); %s", str(e))
            return StorageException('signature failed')

        result = dict()
        result['signature'] = signature
        result['block_ids'] = list(map(encoding_fn, block_hashes))
        return result

    def check_block(self, block_id, encoding='b64') :
        pass

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
                block_status = { 'block_id' : block_id, 'size' : 0, 'expiration' : 0 }
                block_hash = decoding_fn(block_id)

                raw_metadata = txn.get(block_hash, db=mdb)
                if raw_metadata :
                    metadata = BlockMetadata.unpack(raw_metadata)
                    block_status['size'] = metadata.block_size
                    block_status['expiration'] = metadata.expiration_time - current_time
                    if block_status['expiration'] < 0 :
                        block_status['expiration'] = 0

                block_status_list.append(block_status)

        return block_status_list

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
                        logger.debug('expire block %s',base64.urlsafe_b64encode(key).decode())
                        count += 1
                        with self.block_store_env.begin(write=True) as dtxn :
                            assert dtxn.delete(key, db=bdb)
                            assert dtxn.delete(key, db=mdb)

            logger.info('expired %d blocks', count)
        except Exception as e :
            logger.error('garbage collection failed; %s', str(e))
            return None

        return count
