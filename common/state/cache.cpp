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

#include "state.h"

namespace pstate = pdo::state;

#define BLOCK_CACHE_MAX_ITEMS (CACHE_SIZE / FIXED_DATA_NODE_BYTE_SIZE)

#if (FIXED_DATA_NODE_BYTE_SIZE < (1 << 11) || CACHE_SIZE < (1 << 15))
#error "use at least 2KB data node size and 32KB cache size"
#endif

pstate::cache_slots::cache_slots() : data_nodes_(BLOCK_CACHE_MAX_ITEMS, data_node(0))
{
    for (unsigned int i = 0; i < data_nodes_.size(); i++)
    {
        try
        {
            dn_queue_.push(&(data_nodes_[i]));
        }
        catch (const std::exception& e)
        {
            SAFE_LOG_EXCEPTION("cache_slots init error");
            throw;
        }
    }
}

pstate::data_node* pstate::cache_slots::allocate()
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        dn_queue_.empty(), "cache full -- cannot allocate additional cache slots, queue empty");
    data_node* d = dn_queue_.front();
    dn_queue_.pop();

    return d;
}

void pstate::cache_slots::release(data_node** dn)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(dn_queue_.size() >= data_nodes_.size(),
        "cache empty -- nothing to release, nothing to return to queue");
    try
    {
        dn_queue_.push(*dn);
    }
    catch (const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("cache_slots release error");
        throw;
    }
    // delete original pointer
    *dn = NULL;
}

unsigned int pstate::cache_slots::available_slots()
{
    return dn_queue_.size();
}

void pstate::Cache::replacement_policy()
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
            block_cache_.size() + slots_.available_slots() != BLOCK_CACHE_MAX_ITEMS, "cache replacement, invariant not satisfied");

    while (block_cache_.size() >= BLOCK_CACHE_MAX_ITEMS)
    {
        int index_to_remove = -1;
        uint64_t clock = UINT64_MAX;

        for (auto it = block_cache_.begin(); it != block_cache_.end(); ++it)
        {
            block_cache_entry_t& bce = it->second;
            if (!bce.pinned && bce.references == 0)
            {  // candidate for replacement
                if (index_to_remove == -1 || bce.clock < clock)
                {
                    index_to_remove = it->first;
                    clock = bce.clock;
                }
            }
        }
        pdo::error::ThrowIf<pdo::error::RuntimeError>(
            index_to_remove == -1, "cache replacement, no item to replace");
        flush_entry(index_to_remove);
    }
}

void pstate::Cache::drop_entry(unsigned int block_num)
{
    auto it = block_cache_.find(block_num);
    block_cache_entry_t& bce = it->second;
    slots_.release(&(bce.dn));
    block_cache_.erase(it);
}

void pstate::Cache::drop()
{
    while (!block_cache_.empty())
    {
        auto it = block_cache_.begin();
        drop_entry(it->first);
    }
}

void pstate::Cache::flush_entry(unsigned int block_num)
{
    // sync
    sync_entry(block_num);
    // drop
    drop_entry(block_num);
}

void pstate::Cache::flush()
{
    while (!block_cache_.empty())
    {
        auto it = block_cache_.begin();
        flush_entry(it->first);
    }
}

void pstate::Cache::sync_entry(unsigned int block_num)
{
    auto it = block_cache_.find(block_num);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        it == block_cache_.end(), "cache sync entry, entry not found");

    block_cache_entry_t& bce = it->second;

    if (bce.modified)
    {
        StateBlockId new_data_node_id;
        bce.dn->unload(block_warehouse_.state_encryption_key_, new_data_node_id);
        block_warehouse_.update_datablock_id(block_num, new_data_node_id);

        // sync done
        bce.modified = false;
    }
}

void pstate::Cache::sync()
{
    for (auto it = block_cache_.begin(); it != block_cache_.end(); ++it)
    {
        sync_entry(it->first);
    }
}

void pstate::Cache::put(unsigned int block_num, data_node* dn)
{
    //drop the current cache entry (if present)
    if (block_cache_.count(block_num) != 0)
    {
        drop_entry(block_num);
    }

    //add new cache entry
    block_cache_entry_t bce;
    bce.dn = dn;
    bce.references = 0;
    bce.modified = false;
    bce.pinned = false;
    bce.clock = (cache_clock_++);
    block_cache_[block_num] = bce;
}

pstate::data_node& pstate::Cache::retrieve(unsigned int block_num, bool pinned)
{
    if (block_cache_.count(block_num) == 0)
    {  // not in cache
        replacement_policy();

        StateBlockId data_node_id;
        block_warehouse_.get_datablock_id_from_datablock_num(block_num, data_node_id);

        // allocate data node and load block into it
        data_node* dn = slots_.allocate();
        pdo::error::ThrowIf<pdo::error::RuntimeError>(!dn, "slot allocate, null pointer");
        dn->deserialize_original_encrypted_data_id(data_node_id);
        dn->load(block_warehouse_.state_encryption_key_);

        // cache it
        put(block_num, dn);

        if (pinned)
            pin(block_num);
    }
    // now it is in cache, grab it
    block_cache_entry_t& bce = block_cache_[block_num];
    bce.references++;
    return *bce.dn;
}

void pstate::Cache::done(unsigned int block_num, bool modified)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        block_cache_.count(block_num) == 0, "cache done, item not in cache");
    block_cache_entry_t& bce = block_cache_[block_num];
    bce.references--;
    if (modified)
        bce.modified = modified;
}

void pstate::Cache::pin(unsigned int block_num)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        block_cache_.count(block_num) == 0, "cache done, item not in cache");
    block_cache_entry_t& bce = block_cache_[block_num];
    bce.pinned = true;
}

void pstate::Cache::unpin(unsigned int block_num)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        block_cache_.count(block_num) == 0, "cache done, item not in cache");
    block_cache_entry_t& bce = block_cache_[block_num];
    bce.pinned = false;
}

void pstate::Cache::modified(unsigned int block_num)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        block_cache_.count(block_num) == 0, "cache done, item not in cache");
    block_cache_entry_t& bce = block_cache_[block_num];
    bce.modified = true;
}

