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

namespace pdo
{
namespace state
{
    enum kv_operation_e
    {
        GET_OP,
        PUT_OP,
        DEL_OP
    };

// in a trie node, this is the max length of a piece of key that can be indexed
// (SEE trie_node_header_t struct below)
#define MAX_KEY_CHUNK_BYTE_SIZE 15

    struct __attribute__((packed)) trie_node_header_t
    {
        uint8_t isDeleted : 1;
        uint8_t hasNext : 1;
        uint8_t hasChild : 1;
        uint8_t isValue : 1;
        uint8_t keyChunkSize : 4;
    };
    struct __attribute__((packed)) trie_node_h_with_nc_t
    {
        trie_node_header_t hdr;
        block_offset_t next_offset;
        block_offset_t child_offset;
    };
    struct __attribute__((packed)) trie_node_h_with_ncc_t
    {
        trie_node_header_t hdr;
        block_offset_t next_offset;
        block_offset_t child_offset;
        uint8_t key_chunk[MAX_KEY_CHUNK_BYTE_SIZE];
    };

    const trie_node_header_t deleted_trie_header = {1, 0, 0, 0, 0};
    const trie_node_header_t empty_trie_header = {0, 0, 0, 0, 0};
    const trie_node_header_t empty_trie_header_with_nc = {0, 1, 1, 0, 0};
    const trie_node_h_with_nc_t empty_trie_node_h_with_nc = {
        empty_trie_header_with_nc, empty_block_offset};

    class trie_node
    {
    public:
        trie_node_h_with_ncc_t node;
        bool modified = false;
        bool initialized = false;
        block_offset location;

        trie_node() : location(block_offset(empty_block_offset)) {}

        static unsigned int shared_prefix_length(const uint8_t* stored_chunk,
            size_t sc_length,
            const uint8_t* key_chunk,
            size_t kc_length);

        static void delete_trie_node_childless(data_node_io& dn_io,
            trie_node& node);

        static void do_write_value(data_node_io& dn_io,
            trie_node& node,
            const ByteArray& value);
        static void do_read_value_info(
            data_node_io& dn_io, block_offset_t& bo_at, ByteArray& ba_header, size_t& value_size);
        static void do_read_value(
            data_node_io& dn_io, const trie_node& node, ByteArray& value);
        static void do_delete_value(data_node_io& dn_io, trie_node& node);

        static void do_split_trie_node(
            data_node_io& dn_io, trie_node& node, unsigned int spl);
        static size_t new_trie_node_size();

        static void create_node(const ByteArray& key, unsigned int keyChunkBegin, unsigned int keyChunkEnd, trie_node& out_node);
        static void read_trie_node(data_node_io& dn_io, block_offset_t& in_block_offset, trie_node& out_trie_node);
        static void write_trie_node(data_node_io& dn_io, trie_node& in_trie_node);

        static void init_trie_root(data_node_io& dn_io);
        static void operate_trie_non_recursive(
            data_node_io& dn_io,
            const kv_operation_e operation,
            const ByteArray& kvkey,
            const ByteArray& in_value,
            ByteArray& out_value);
    };
}
}
