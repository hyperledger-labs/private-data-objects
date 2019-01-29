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

#include <map>
#include <queue>
#include "basic_kv.h"
#include "types.h"

#define FIXED_DATA_NODE_BYTE_SIZE (1 << 13)  // 8 KB
#define CACHE_SIZE (1 << 22)                 // 4 MB

namespace pdo
{
namespace state
{
    struct __attribute__((packed)) block_offset_t
    {
        unsigned int block_num;
        unsigned int bytes;  // usually treated as an offset within a block
    };

    bool operator==(const block_offset_t& lhs, const block_offset_t& rhs);
    bool operator!=(const block_offset_t& lhs, const block_offset_t& rhs);

    const block_offset_t empty_block_offset = {0, 0};

    class block_offset
    {
    public:
        block_offset_t block_offset_ = empty_block_offset;

        block_offset(const block_offset_t& b) : block_offset_(b) {}

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

    class block_warehouse
    {
    private:
        pdo::state::StateBlockIdArray blockIds_ = {};

    public:
        const ByteArray state_encryption_key_;

        block_warehouse(const ByteArray& state_encryption_key)
            : state_encryption_key_(state_encryption_key)
        {
        }

        void serialize_block_ids(pdo::state::StateNode& node);
        void deserialize_block_ids(pdo::state::StateNode& node);

        void update_datablock_id(unsigned int data_block_num, pdo::state::StateBlockId& newId);

        void add_block_id(pdo::state::StateBlockId& id);

        void remove_empty_block_ids();
        void remove_block_id_from_datablock_num(unsigned int data_block_num);

        void get_datablock_id_from_datablock_num(
            unsigned int data_block_num, pdo::state::StateBlockId& outId);
        unsigned int get_root_block_num();
        unsigned int get_last_block_num();
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

    enum kv_operation_e
    {
        GET_OP,
        PUT_OP,
        DEL_OP
    };

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

    class cache_slots
    {
    public:
        cache_slots();
        data_node* allocate();
        void release(data_node** dn);
        unsigned int available_slots();

    private:
        // the data nodes constitute the cache slots
        // pointers to these slots are initially pushed in the queue,
        // and then popped/pushed as they are allocated/released
        std::vector<data_node> data_nodes_;
        std::queue<data_node*> dn_queue_;
    };

    class free_space_collector
    {
        typedef struct {
            block_offset_t bo;
            unsigned int length;
        } free_space_item_t;

    private:
        bool is_collection_modified = false;
        bool is_fsi_deferred = false;
        free_space_item_t deferred_fsi;

        std::vector<free_space_item_t> free_space_collection;

        bool are_adjacent(const block_offset_t& bo1, const unsigned& length1, const block_offset_t& bo2);
        void insert_free_space_item(std::vector<free_space_item_t>::iterator& it, free_space_item_t& fsi);
        void do_collect(free_space_item_t& fsi);

    public:
        StateBlockId original_block_id_of_collection;

        void collect(const block_offset_t& bo, const unsigned int& length);
        bool allocate(const unsigned int& length, block_offset_t& out_bo);
        bool collection_modified();
        void serialize_in_data_node(data_node &out_dn);
        void deserialize_from_data_node(data_node &in_dn);
    };

    class Cache
    {
    private:
        // the block_warehouse_ reference is related to the block_warehouse member of dn_io
        block_warehouse& block_warehouse_;
    public:
        struct block_cache_entry_t
        {
            bool pinned;
            unsigned int references;
            bool modified;
            uint64_t clock;
            data_node* dn;
        };

        Cache(block_warehouse& bw): block_warehouse_(bw) {}

        std::map<unsigned int, block_cache_entry_t> block_cache_;
        cache_slots slots_;
        uint64_t cache_clock_ = 0;

        void replacement_policy();
        void drop_entry(unsigned int block_num);
        void drop();
        void flush_entry(unsigned int block_num);
        void flush();
        void sync_entry(unsigned int block_num);
        void sync();
        void put(unsigned int block_num, data_node* dn);
        data_node& retrieve(unsigned int block_num, bool pinned);
        void done(unsigned int block_num, bool modified);
        void pin(unsigned int block_num);
        void unpin(unsigned int block_num);
        void modified(unsigned int block_num);
    };

    class data_node_io
    {
    public:
        block_warehouse block_warehouse_;
        free_space_collector free_space_collector_;
        // append_dn points to a data note pinned in cache
        data_node* append_dn_;
        Cache cache_;

        data_node_io(const ByteArray& key) : block_warehouse_(key), cache_(block_warehouse_) {}
        void initialize(pdo::state::StateNode& node);

        void init_append_data_node();
        void add_and_init_append_data_node();
        void add_and_init_append_data_node_cond(bool cond);
        void consume_add_and_init_append_data_node();
        void consume_add_and_init_append_data_node_cond(bool cond);
        void block_offset_for_appending(block_offset_t& out_bo);

        void write_across_data_nodes(const ByteArray& buffer, unsigned int write_from, const block_offset_t& bo_at);
        void read_across_data_nodes(const block_offset_t& bo_at, unsigned int length, ByteArray& outBuffer);
    };

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

        static void do_operate_trie_child(data_node_io& dn_io,
            trie_node& node,
            const kv_operation_e operation,
            const unsigned int depth,
            const ByteArray& kvkey,
            const ByteArray& in_value,
            ByteArray& value);
        static void do_operate_trie_next(data_node_io& dn_io,
            trie_node& node,
            const kv_operation_e operation,
            const unsigned int depth,
            const ByteArray& kvkey,
            const ByteArray& in_value,
            ByteArray& value);

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

        static void operate_trie(data_node_io& dn_io,
            trie_node& node,
            const kv_operation_e operation,
            const unsigned int depth,
            const ByteArray& kvkey,
            const ByteArray& in_value,
            ByteArray& value);
        static void init_trie_root(data_node_io& dn_io);
        static void operate_trie_root(data_node_io& dn_io,
            const kv_operation_e operation,
            const ByteArray& kvkey,
            const ByteArray& in_value,
            ByteArray& value);
    };

    const ByteArray empty_state_encryption_key_ = ByteArray(16, 0);

    class State_KV : public Basic_KV
    {
        typedef enum
        {
            KV_CREATE,
            KV_OPEN
        } kv_start_mode_e;

    protected:
        pdo::state::StateNode rootNode_;
        const ByteArray state_encryption_key_;
        data_node_io dn_io_;
        kv_start_mode_e kv_start_mode;

    public:
        State_KV(StateBlockId& id);
        State_KV(const StateBlockId& id, const ByteArray& key);
        State_KV(const ByteArray& key);

        void Finalize(ByteArray& id);

        ByteArray Get(const ByteArray& key);
        void Put(const ByteArray& key, const ByteArray& value);
        void Delete(const ByteArray& key);
    };
}
}
