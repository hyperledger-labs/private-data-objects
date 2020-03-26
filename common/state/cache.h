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

#include <map>
#include <queue>

#define CACHE_SIZE (1 << 22)                 // 4 MB

namespace pdo
{
namespace state
{
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

    class Cache
    {
    private:
        // the block_warehouse_ reference is related to the block_warehouse member of dn_io
        block_warehouse& block_warehouse_;
        unsigned int synced_entries_;

        void replacement_policy_MRU();

    public:
        struct block_cache_entry_t
        {
            bool pinned;
            unsigned int references;
            bool modified;
            uint64_t clock;
            data_node* dn;
        };

        Cache(block_warehouse& bw): block_warehouse_(bw), synced_entries_(0) {}

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
        unsigned int synced_entries();
    };
}
}
