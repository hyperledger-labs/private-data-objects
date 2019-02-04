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

#include "state.h"

namespace pstate = pdo::state;

bool pstate::free_space_collector::are_adjacent(const block_offset_t& bo1, const unsigned& length1, const block_offset_t& bo2)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(bo1.block_num > bo2.block_num ||
        (bo1.block_num == bo2.block_num && bo1.bytes > bo2.bytes),
        "free space collector, adjancency error");
    block_offset_t bo = bo1;
    data_node::advance_block_offset(bo, length1);
    return (bo == bo2);
}

void pstate::free_space_collector::insert_free_space_item(std::vector<free_space_item_t>::iterator& it, free_space_item_t& fsi)
{
    //first check if it can merge with previous
    if(it != free_space_collection.begin())
    {
        auto prev_it = std::prev(it);
        if(are_adjacent(prev_it->bo, prev_it->length, fsi.bo))
        {
            //update item to be inserted
            fsi.bo = prev_it->bo;
            fsi.length += prev_it->length;
            //remove previous item
            it = free_space_collection.erase(prev_it);
        }
    }
    //also, check if it can merge with current
    if(it != free_space_collection.end() && are_adjacent(fsi.bo, fsi.length, it->bo))
    {
        //item to be inserted is the same, just increase length
        fsi.length += it->length;
        it = free_space_collection.erase(it);
    }
    //any merge done, now insert
    free_space_collection.insert(it, fsi);
}

void pstate::free_space_collector::do_collect(free_space_item_t& fsi)
{
    std::vector<free_space_item_t>::iterator it;

    for(it = free_space_collection.begin(); it != free_space_collection.end(); it++)
    {
        if(fsi.bo.block_num < it->bo.block_num || //if the item location preceeds the current one, insert!
            (fsi.bo.block_num == it->bo.block_num && fsi.bo.bytes < it->bo.bytes))
        {
            insert_free_space_item(it, fsi);
            return;
        }

        //no insert, go to next
    }

    // no merge in loop, then insert/merge at end of vector
    insert_free_space_item(it, fsi);

    is_collection_modified = true;
}

void pstate::free_space_collector::collect(const block_offset_t& bo, const unsigned int& length)
{
    if(length ==0) // nothing to collect
    {
        return;
    }

    if(is_fsi_deferred)
    {
        do_collect(deferred_fsi);
        is_fsi_deferred = false;
    }

    deferred_fsi = {bo, length};
    is_fsi_deferred= true;
}

bool pstate::free_space_collector::allocate(const unsigned int& length, block_offset_t& out_bo)
{
    bool space_found = false;

    if(is_fsi_deferred)
    {
        is_fsi_deferred=false;

        if(deferred_fsi.length == length)
        {
            out_bo = deferred_fsi.bo;
            return true;
        }

        //else, collect now and continue with allocation
        do_collect(deferred_fsi);
    }

    for(auto it = free_space_collection.begin(); it != free_space_collection.end(); it++)
    {
        if(it->length >= length)
        {
            space_found = true;
            //return the block offset
            out_bo = it->bo;

            if(it->length == length)
            {
                //the requested length match, so remove item
                free_space_collection.erase(it);
            }
            else
            {
                //item has more space than necessary, so update it
                data_node::advance_block_offset(it->bo, length);
                it->length -= length;
            }

            is_collection_modified = true;

            break;
        }
    }

    return space_found;
}

bool pstate::free_space_collector::collection_modified()
{
    return is_collection_modified;
}

void pstate::free_space_collector::serialize_in_data_node(data_node &out_dn)
{
    if(is_fsi_deferred)
    {
        do_collect(deferred_fsi);
        is_fsi_deferred = false;
    }

    //out_dn must be a dedicated data node, so let us check it is completely free
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        out_dn.free_bytes() != data_node::data_end_index() - data_node::data_begin_index(),
    "serialize free space collector, data node not dedicated");

    unsigned int items=0;
    block_offset_t bo = {out_dn.get_block_num(), data_node::data_begin_index()};
    for(auto it = free_space_collection.begin(); it != free_space_collection.end(); it++)
    {
        if(out_dn.free_bytes() < sizeof(free_space_item_t))
        {
            //WARNING: items that do not fit into the data node are discarded
            break;
        }
        ByteArray ba_free_space_item((uint8_t*)&(*it), (uint8_t*)&(*it) + sizeof(free_space_item_t));
        out_dn.write_at(ba_free_space_item, 0, bo);
        data_node::advance_block_offset(bo, sizeof(free_space_item_t));
        items++;
    }
}

void pstate::free_space_collector::deserialize_from_data_node(data_node &in_dn)
{
    //ASSUMPTION: the data node is dedicated to contain the free space collection vector
    unsigned int bytes_to_read = data_node::data_end_index() - data_node::data_begin_index() - in_dn.free_bytes();
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        bytes_to_read % sizeof(free_space_item_t) != 0,
        "deserialize free space collector, readable bytes not a multiple of item size");
    block_offset_t bo = {in_dn.get_block_num(), data_node::data_begin_index()};
    ByteArray ba_free_space_item;
    while(bytes_to_read)
    {
        in_dn.read_at(bo, sizeof(free_space_item_t), ba_free_space_item);
        data_node::advance_block_offset(bo, sizeof(free_space_item_t));
        bytes_to_read -= sizeof(free_space_item_t);

        free_space_collection.push_back(*((free_space_item_t*)ba_free_space_item.data()));
        ba_free_space_item.clear();
    }
}
