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
#include "basic_kv.h"
#include <map>
#include <queue>

namespace pdo
{
    namespace state
    {
        struct __attribute__((packed)) block_offset_t {
            unsigned int block_num;
            unsigned int bytes; //usually treated as an offset within a block
        };

        bool operator==(const block_offset_t& lhs, const block_offset_t& rhs);
        bool operator!=(const block_offset_t& lhs, const block_offset_t& rhs);

        const block_offset_t empty_block_offset = {0, 0};

        class block_offset {
            public:
            block_offset_t block_offset_ = empty_block_offset;

            static unsigned int offset_size();
            static unsigned int serialized_offset_to_block_num(const ByteArray& serialized_offset);
            static unsigned int serialized_offset_to_bytes(const ByteArray& serialized_offset);
            static ByteArray to_ByteArray(const block_offset_t bo);
            void serialize_offset(ByteArray& outBuffer);
            void deserialize_offset(const ByteArray& inBuffer);
            void deserialize_offset(const block_offset_t bo);
            void empty();
            bool is_empty();
            ByteArray to_ByteArray();
        };

        class block_warehouse {
            public:
            pdo::state::StateBlockIdArray blockIds_ = {};
            unsigned int last_appended_data_block_num_;
            const ByteArray state_encryption_key_;

            block_warehouse(const ByteArray& state_encryption_key) : state_encryption_key_(state_encryption_key) {}

            void serialize_block_ids(pdo::state::StateNode& node);
            void deserialize_block_ids(pdo::state::StateNode& node);
            void update_block_id(pdo::state::StateBlockId& prevId, pdo::state::StateBlockId& newId);
            void update_datablock_id(unsigned int data_block_num, pdo::state::StateBlockId& newId);
            void add_block_id(pdo::state::StateBlockId& id);
            void add_datablock_id(pdo::state::StateBlockId& id);
            void get_datablock_id_from_datablock_num(unsigned int data_block_num, pdo::state::StateBlockId& outId);
            void get_last_datablock_id(pdo::state::StateBlockId& outId);
            unsigned int get_root_block_num();
        };

// in a trie node, this is the max length of a piece of key that can be indexed
// (SEE trie_node_header_t struct below)
#define MAX_KEY_CHUNK_BYTE_SIZE 15

        struct __attribute__((packed)) trie_node_header_t {
            uint8_t isDeleted : 1;
            uint8_t hasNext : 1;
            uint8_t hasChild : 1;
            uint8_t isValue : 1;
            uint8_t keyChunkSize : 4;
        };
        struct __attribute__((packed)) trie_node_h_with_n_t {
            struct trie_node_header_t hdr;
            struct block_offset_t next_offset;
        };
        struct __attribute__((packed)) trie_node_h_with_c_t {
            struct trie_node_header_t hdr;
            struct block_offset_t child_offset;
        };
        struct __attribute__((packed)) trie_node_h_with_nc_t {
            trie_node_header_t hdr;
            block_offset_t next_offset;
            block_offset_t child_offset;
        };

        const trie_node_header_t deleted_trie_header        = {1, 0, 0, 0, 0};
        const trie_node_header_t empty_trie_header          = {0, 0, 0, 0, 0};
        const trie_node_header_t empty_trie_header_with_n   = {0, 1, 0, 0, 0};
        const trie_node_header_t empty_trie_header_with_c   = {0, 0, 1, 0, 0};
        const trie_node_header_t empty_trie_header_with_nc  = {0, 1, 1, 0, 0};
        const trie_node_h_with_n_t empty_trie_node_h_with_n   = {empty_trie_header_with_n, empty_block_offset};
        const trie_node_h_with_c_t empty_trie_node_h_with_c   = {empty_trie_header_with_c, empty_block_offset};
        const trie_node_h_with_nc_t empty_trie_node_h_with_nc = {empty_trie_header_with_nc, empty_block_offset};

        enum kv_operation_e {
                GET_OP,
                PUT_OP,
                DEL_OP
        };

        class data_node {
            private:
            ByteArray data_;
            StateBlockId originalEncryptedDataNodeId_;
            unsigned block_num_;
            unsigned int free_bytes_;

            public:
            ByteArray make_offset(unsigned int block_num, unsigned int bytes_off);
            data_node(unsigned int block_num);
            unsigned int get_block_num();
            void serialize_data_header();
            void decrypt_and_deserialize_data(const ByteArray& inEncryptedData, const ByteArray& state_encryption_key);
            void deserialize_data(const ByteArray& inData);
            void deserialize_block_num_from_offset(ByteArray& offset);
            void deserialize_original_encrypted_data_id(StateBlockId& id);
            unsigned int free_bytes();
            bool enough_space_for_value(bool continue_writing);
            unsigned int write(const ByteArray& buffer, unsigned int write_from, ByteArray& returnOffSet);
            unsigned int read(
                            const ByteArray& offset,
                            ByteArray& outBuffer,
                            bool continue_reading,
                            unsigned int continue_reading_bytes);
            uint8_t* offset_to_pointer(const ByteArray& offset);
            void load(const ByteArray& state_encryption_key);
            void unload(const ByteArray& state_encryption_key, StateBlockId& outEncryptedDataNodeId);

            trie_node_header_t* write_trie_node(
                                    bool isDeleted,
                                    bool hasNext,
                                    bool hasChild,
                                    const ByteArray& key,
                                    unsigned int keyChunkBegin,
                                    unsigned int keyChunkEnd,
                                    ByteArray& returnOffset);
        };

        class cache_slots {
            public:
            cache_slots();
            data_node* allocate();
            void release(data_node** dn);
            private:
            // the data nodes constitute the cache slots
            // pointers to these slots are initially pushed in the queue,
            // and then popped/pushed as they are allocated/released
            std::vector<data_node> data_nodes_;
            std::queue<data_node*> dn_queue_;
        };

        class data_node_io {
            public:
            block_warehouse block_warehouse_;
            //append_dn points to a data note pinned in cache
            data_node* append_dn_;

            data_node_io(const ByteArray& key) : block_warehouse_(key) {}
            void init_append_data_node();
            void add_and_init_append_data_node();
            void add_and_init_append_data_node_cond(bool cond);

            struct block_cache_entry_t {
                bool pinned;
                unsigned int references;
                bool modified;
                uint64_t clock;
                data_node* dn;
            };
            std::map<unsigned int, block_cache_entry_t> block_cache_;
            cache_slots cache_slots_;
            uint64_t cache_clock_ = 0;

            void cache_replacement_policy();
            void cache_dump();
            void cache_flush_entry(unsigned int block_num);
            void cache_flush();
            void cache_put(unsigned int block_num, data_node* dn);
            data_node& cache_retrieve(unsigned int block_num, bool pinned);
            void cache_done(unsigned int block_num, bool modified);
            void cache_pin(unsigned int block_num);
            void cache_unpin(unsigned int block_num);
            void cache_modified(unsigned int block_num);
        };

        class trie_node
        {
            public:
            static block_offset_t* goto_next_offset(trie_node_header_t* header);
            static block_offset_t* goto_child_offset(trie_node_header_t* header);
            static uint8_t* goto_key_chunk(trie_node_header_t* header);

            static void resize_key_chunk(trie_node_header_t* header, unsigned int new_size);
            static void delete_child_offset(trie_node_header_t* header);
            static void delete_next_offset(trie_node_header_t* header);

            static unsigned int shared_prefix_length(
                                    const uint8_t* stored_chunk,
                                    size_t sc_length,
                                    const uint8_t* key_chunk,
                                    size_t kc_length);

            static void delete_trie_node(trie_node_header_t* header);
            static void delete_trie_node_childless(trie_node_header_t* header, block_offset& out_bo_new);
            static void update_trie_node_next(
                                trie_node_header_t* header,
                                block_offset_t* bo_next,
                                block_offset& out_bo_new);
            static void update_trie_node_child(
                                trie_node_header_t* header,
                                block_offset_t* bo_child,
                                block_offset& out_bo_new);

            static void do_operate_trie_child(
                            data_node_io& dn_io,
                            trie_node_header_t* trie_node_header,
                            const kv_operation_e operation,
                            const unsigned int depth,
                            const ByteArray& kvkey,
                            ByteArray& value,
                            block_offset& outBlockOffset);
            static void do_operate_trie_next(
                            data_node_io& dn_io,
                            trie_node_header_t* trie_node_header,
                            const kv_operation_e operation,
                            const unsigned int depth,
                            const ByteArray& kvkey,
                            ByteArray& value,
                            block_offset& outBlockOffset);

            static void do_write_value(
                            data_node_io& dn_io,
                            trie_node_header_t* header,
                            const ByteArray& value,
                            block_offset& outBlockOffset);
            static void do_read_value(data_node_io& dn_io, trie_node_header_t* trie_node_header, ByteArray& value);
            static void do_delete(trie_node_header_t* header);

            static void do_split_trie_node(
                            data_node_io& dn_io,
                            trie_node_header_t* header,
                            unsigned int spl);
            static size_t new_trie_node_size();

            static trie_node_header_t* append_trie_node(
                    data_node_io& dn_io,
                    const ByteArray& kvkey,
                    const unsigned int key_begin,
                    const unsigned int key_end,
                    block_offset& outBlockOffset);

            static void operate_trie(
                    data_node_io& dn_io,
                    trie_node_header_t* trie_node_header,
                    const kv_operation_e operation,
                    const unsigned int depth,
                    const ByteArray& kvkey,
                    ByteArray& value,
                    block_offset& outBlockOffset);
            static void init_trie_root(data_node_io& dn_io);
            static void operate_trie_root(
                            data_node_io& dn_io,
                            const kv_operation_e operation,
                            const ByteArray& kvkey,
                            ByteArray& value);
        };

        const ByteArray empty_state_encryption_key_ = ByteArray(16, 0);

        class State_KV : public Basic_KV
        {
            protected:
            pdo::state::StateNode rootNode_;
            const ByteArray state_encryption_key_;
            data_node_io dn_io_;

            public:
            State_KV(StateBlockId& id);
            State_KV(const StateBlockId& id, const ByteArray& key);
            State_KV(const ByteArray& key);
            ~State_KV();

            void Finalize(ByteArray& id);

            ByteArray Get(const ByteArray& key);
            void Put(const ByteArray& key, const ByteArray& value);
            void Delete(const ByteArray& key);
        };
    }
}
