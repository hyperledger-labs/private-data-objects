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

#include "types.h"
#include "state_status.h"
#include "StateBlock.h"
#include "StateUtils.h"

namespace pdo 
{
    namespace state 
    {
        // State Abstraction Layer
        class sal {
        public:
            /*
                The SAL is initialized using the state root (for extrinsic state) in the contract state.
                Then, other code that uses the SAL (e.g., a key value store) is assumed to have the id
                (i.e., sha256 hash) of the data it wants to open and read/write.
            */
            sal();

            /*
                It initializes the SAL starting from the root id.
                If the id is empty it creates a new block to put ids.
                If the id is not empty it attempts to retrieve the correspondig data block,
                and makes it available for sal_open.
                The caller can check what ids can be opened through sal_list.
            */
            void init(ByteArray &id);

            /*
                The SAL uninitialization returns a copy of the identity (i.e., root hash).
                This is the root of the extrinsic state.
            */
            state_status_t uninit(pdo::state::StateBlockId* rootId);

            /*
                The SAL list function returns the id's of the children (of the main block)
                that can be later opened
            */
            StateBlockIdRefArray list();

            /*
                The SAL Initialized function simply returns whether the SAL is initialized or not
            */
            bool initialized();

            /*
                The open function takes as input an id.
                If the id is empty, a new child is created
                (e.g., the root hash of a KV store that has just been created).
                If the id is not empty, then this should match a child of the current node in the hierarchy.
                In case of success, a handle is returned, and can be used for reading and writing data.
            */
            state_status_t open(ByteArray& id, void **handle);

            /*
                The read operation appends up to 'bytes' of data into the output buffer,
                starting from the current cursor.
                If the read operation overflows, it still appends as many bytes as possible and returns an EOD
                (End Of Data) value.
            */
            state_status_t read(void* handle, size_t bytes, ByteArray &output_buffer);

            /*
                The write operation takes an input buffer an writes the data in the opened state,
                starting from the current cursor.
            */
            state_status_t write(void* handle, ByteArray &input_buffer);

            /*
                The seek operation moves the cursor backward or forward of a specified offset.
                The highest negative (resp. positive) offset is interpreted 
                as the first (resp. last) byte of the state.
            */
            state_status_t seek(void* handle, int64_t offset);

            /*
                The truncate_here operation drops all data after the cursor,
                reduces the size of the data block,
                and leaves the cursor at the end of the block.
            */
            state_status_t truncate_here(void* handle);

            /*
                The close operation frees resources, evicts the blocks that are now unnecessary and returns
            */
            state_status_t close(void **handle, pdo::state::StateBlockId* id);

        protected:
            bool initialized_ = false;
            pdo::state::StateNode* rootNode;
        };
    }
}

/*
    Global variable defined in the SAL source code file.
*/
extern pdo::state::sal g_sal;
