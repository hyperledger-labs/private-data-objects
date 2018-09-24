/* Copyright 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "pdo_error.h"
#include "types.h"

namespace pdo
{
    namespace block_store
    {
        /**
         * Initialize the block store - must be called before performing gets/puts
         * Primary expected use: python / untrusted side
         *
         * @return
         *  Success (return PDO_SUCCESS) - Block store ready to use
         *  Failure (return nonzero) - Block store is unusable
         */
        pdo_err_t BlockStoreInit();

        /**
         * Gets the size of a block in the block store
         * Primary expected use: ocall
         *
         * @param inKey         pointer to raw key byte array
         * @param inKeySize     length of inKey
         * @param outValueSize  size (in # bytes) of value will be written here
         *
         * @return
         *  Success (return 0) - outValueSize set to the number of bytes of raw value
         *  Failure (return nonzero) - outValueSize undefined
         */
        int BlockStoreHead(
            const uint8_t* inKey,
            const size_t inKeySize,
            size_t* outValueSize
            );

        /**
         * Gets a block from the block store
         * Primary expected use: ocall
         *
         * @param inKey         pointer to raw key byte array
         * @param inKeySize     length of inKey
         * @param outValue      buffer where value should be copied
         * @param inValueSize   length of caller's outValue buffer
         *
         * @return
         *  Success (return 0) - outValue contains the requested block
         *  Failure (return nonzero) - outValue unchanged
         */
        int BlockStoreGet(
            const uint8_t* inKey,
            const size_t inKeySize,
            uint8_t *outValue,
            const size_t inValueSize
            );

        /**
         * Puts a block into the block store
         * Primary expected use: ocall
         *
         * @param inKey         pointer to raw key byte array
         * @param inKeySize     length of inKey
         * @param inValue       pointer to raw value byte array
         * @param inValueSize   length of inValue
         *
         * @return
         *  Success (return 0) - key->value stored
         *  Failure (return nonzero) - block store unchanged
         */
        int BlockStorePut(
            const uint8_t* inKey,
            const size_t inKeySize,
            const uint8_t* inValue,
            const size_t inValueSize
            );

        /**
         * Gets the size of a block in the block store
         * Primary expected use: python / untrusted side
         *
         * @param inKey     raw bytes
         *
         * @return
         *  Block present - return size of block
         *  Block not present - return -1
         */
        int BlockStoreHead(
            const ByteArray& inKey
            );

        /**
         * Gets a block from the block store
         * Primary expected use: python / untrusted side
         *
         * @param inKey     raw bytes
         * @param outValue  raw bytes
         *
         * @return
         *  Success (return 0) - outValue resized and contains block data
         *  Failure (return nonzero) - outValue unchanged
         */
        pdo_err_t BlockStoreGet(
            const ByteArray& inKey,
            ByteArray& outValue
            );

        /**
         * Puts a block into the block store
         * Primary expected use: python / untrusted side
         *
         * @param inKey     raw bytes
         * @param inValue   raw bytes
         *
         * @return
         *  Success (return PDO_SUCCESS) - key->value stored
         *  Failure (return nonzero) - block store unchanged
         */
        pdo_err_t BlockStorePut(
            const ByteArray& inKey,
            const ByteArray& inValue
            );

    } /* contract */
} /* pdo */
