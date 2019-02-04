/* Copyright 2019 Intel Corporation
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

#define FIXED_DATA_NODE_BYTE_SIZE (1 << 13)  // 8 KB

namespace pdo
{
namespace state
{
    class data_node
    {
    private:
        ByteArray data_;
        StateBlockId originalEncryptedDataNodeId_;
        unsigned block_num_;
        unsigned int free_bytes_;

        void decrypt_and_deserialize_data(
            const ByteArray& inEncryptedData, const ByteArray& state_encryption_key);

    public:
        ByteArray make_offset(unsigned int block_num, unsigned int bytes_off);
        data_node(unsigned int block_num);
        static unsigned int data_begin_index();
        static unsigned int data_end_index();
        unsigned int get_block_num();
        void cursor(block_offset_t& out_bo);
        void serialize_data_header();
        void deserialize_original_encrypted_data_id(StateBlockId& id);
        unsigned int free_bytes();
        void consume_free_space(unsigned int length);
        static void advance_block_offset(block_offset_t& bo, unsigned int length);
        unsigned int write_at(const ByteArray& buffer, unsigned int write_from, const block_offset_t& bo_at);
        unsigned int read_at(const block_offset_t& bo_at, unsigned int bytes, ByteArray& outBuffer);
        void load(const ByteArray& state_encryption_key);
        void unload(const ByteArray& state_encryption_key, StateBlockId& outEncryptedDataNodeId);
    };
}
}
