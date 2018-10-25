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
    /*
     * Many different implementations of this block store API exist within PDO
     * The idea is that every implementation has these methods, but they may
     * have their own methods (particularly initialization) in their own
     * specific namespaces
     */
    namespace block_store
    {
        /**
         * Gets the size of a block in the block store
         * Primary expected use: ocall
         *
         * @param inId          pointer to id byte array
         * @param inIdSize      length of inId
         * @param outIsPresent  [output] true if value is present, false if not
         * @param outValueSize  [output] size (in # bytes) of value if present
         *
         * @return
         *  PDO_SUCCESS  outValueSize set to the number of bytes of value
         *  else         failed, outValueSize undefined
         */
        pdo_err_t BlockStoreHead(
            const uint8_t* inId,
            const size_t inIdSize,
            bool* outIsPresent,
            size_t* outValueSize
            );

        /**
         * Gets a block from the block store
         * Primary expected use: ocall
         *
         * @param inId          pointer to id byte array
         * @param inIdSize      length of inId
         * @param outValue      [output] buffer where value should be copied
         * @param inValueSize   length of caller's outValue buffer
         *
         * @return
         *  PDO_SUCCESS  outValue contains the requested block
         *  else         failed, outValue unchanged
         */
        pdo_err_t BlockStoreGet(
            const uint8_t* inId,
            const size_t inIdSize,
            uint8_t *outValue,
            const size_t inValueSize
            );

        /**
         * Puts a block into the block store
         * Primary expected use: ocall
         *
         * @param inId          pointer to id byte array
         * @param inIdSize      length of inId
         * @param inValue       pointer to value byte array
         * @param inValueSize   length of inValue
         *
         * @return
         *  PDO_SUCCESS  id->value stored
         *  else         failed, block store unchanged
         */
        pdo_err_t BlockStorePut(
            const uint8_t* inId,
            const size_t inIdSize,
            const uint8_t* inValue,
            const size_t inValueSize
            );

        /**
         * Gets the size of a block in the block store
         * Primary expected use: python / untrusted side
         *
         * @param inId          id byte array
         * @param outIsPresent  [output] true if value is present, false if not
         * @param outValueSize  [output] size (in # bytes) of value if present
         *
         * @return
         *  PDO_SUCCESS  outValueSize set to the number of bytes of value
         *  else         failed, outValueSize undefined
         */
        pdo_err_t BlockStoreHead(
            const ByteArray& inId,
            bool* outIsPresent,
            size_t* outValueSize
            );

        /**
         * Gets a block from the block store
         * Primary expected use: python / untrusted side
         *
         * @param inId      id byte array
         * @param outValue  [output] where block data will be written
         *
         * @return
         *  PDO_SUCCESS   outValue contains the requested block
         *  PDO_ERR_VALUE block was not present in the block store
         *  else          failed, outValue unchanged
         */
        pdo_err_t BlockStoreGet(
            const ByteArray& inId,
            ByteArray& outValue
            );

        /**
         * Puts a block into the block store
         * Primary expected use: python / untrusted side
         *
         * @param inId      id byte array
         * @param inValue   block data to write
         *
         * @return
         *  PDO_SUCCESS  id->value stored
         *  else         failed, block store unchanged
         */
        pdo_err_t BlockStorePut(
            const ByteArray& inId,
            const ByteArray& inValue
            );

    } /* contract */
} /* pdo */
