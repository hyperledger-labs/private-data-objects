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

void pstate::data_node_io::block_offset_for_appending(block_offset_t& out_bo)
{
    append_dn_->cursor(out_bo);
}

void pstate::data_node_io::initialize(pdo::state::StateNode& node)
{
    // deserialize blocks ids in root block
    block_warehouse_.deserialize_block_ids(node);

    //deserialize free space allocator, and remove last data node
    {
        //get the data node of the free space collection
        unsigned int free_space_collection_block_num = block_warehouse_.get_last_block_num();
        data_node& fsc_dn = cache_.retrieve(free_space_collection_block_num, false);
        //save the identity of the data node containing it
        block_warehouse_.get_datablock_id_from_datablock_num(
            free_space_collection_block_num, free_space_collector_.original_block_id_of_collection);
        //deserialize the collection
        free_space_collector_.deserialize_from_data_node(fsc_dn);
        //rmeove last data node
        cache_.done(block_warehouse_.get_last_block_num(), false);
        block_warehouse_.remove_block_id_from_datablock_num(free_space_collection_block_num);
    }

    init_append_data_node();
}

void pstate::data_node_io::init_append_data_node()
{
    // the append node to be inited already exists, grab it
    StateBlockId data_node_id;
    unsigned int append_data_node_block_num = block_warehouse_.get_last_block_num();
    block_warehouse_.get_datablock_id_from_datablock_num(
        append_data_node_block_num, data_node_id);
    append_dn_ = &cache_.retrieve(append_data_node_block_num, true);
    cache_.done(append_data_node_block_num,
        false);  // nobody is using it now
}

void pstate::data_node_io::add_and_init_append_data_node()
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(append_dn_->free_bytes() == data_node::data_end_index() - data_node::data_begin_index(),
        "appending new data node after empty one");

    unsigned int append_data_node_block_num = block_warehouse_.get_last_block_num();

    // make space in cache if necessary
    cache_.unpin(append_data_node_block_num);
    cache_.replacement_policy();

    // allocate and initialized data node
    append_data_node_block_num ++;
    append_dn_ = cache_.slots_.allocate();
    pdo::error::ThrowIf<pdo::error::RuntimeError>(!append_dn_, "slot allocate, null pointer");
    *append_dn_ = data_node(append_data_node_block_num);

    // put and pin it in cache
    cache_.put(append_data_node_block_num, append_dn_);
    cache_.pin(append_data_node_block_num);
    cache_.modified(append_data_node_block_num);

    // add empty id in list
    StateBlockId dn_id(STATE_BLOCK_ID_LENGTH, 0);
    block_warehouse_.add_block_id(dn_id);
}

void pstate::data_node_io::consume_add_and_init_append_data_node()
{
    //consume remaining space (if any) in data node, for later collection
    block_offset_t bo;
    block_offset_for_appending(bo);
    if(append_dn_->free_bytes() > 0)
    {
        free_space_collector_.collect(bo, append_dn_->free_bytes());
        append_dn_->consume_free_space(append_dn_->free_bytes());
    }

    add_and_init_append_data_node();
}

void pstate::data_node_io::add_and_init_append_data_node_cond(bool cond)
{
    if (cond)
        pstate::data_node_io::add_and_init_append_data_node();
}

void pstate::data_node_io::consume_add_and_init_append_data_node_cond(bool cond)
{
    if (cond)
        pstate::data_node_io::consume_add_and_init_append_data_node();
}

void pstate::data_node_io::write_across_data_nodes(const ByteArray& buffer, unsigned int write_from, const block_offset_t& bo_at)
{
    block_offset_t bo = bo_at;

    unsigned int bytes_written, total_bytes_written = 0;

    // start writing value
    while(total_bytes_written < buffer.size())
    {
        //if we are appending and the block offset touches a new data node, make sure to append a new one to the list
        add_and_init_append_data_node_cond(bo.block_num > block_warehouse_.get_last_block_num());

        data_node& dn = cache_.retrieve(bo.block_num, false);
        bytes_written = dn.write_at(buffer, total_bytes_written, bo);
        cache_.done(bo.block_num, bytes_written > 0);

        //increment written bytes and advance block offset
        total_bytes_written += bytes_written;
        data_node::advance_block_offset(bo, bytes_written);
    }
}

void pstate::data_node_io::read_across_data_nodes(const block_offset_t& bo_at, unsigned int length, ByteArray& out_buffer)
{
    block_offset_t bo = bo_at;

    unsigned int bytes_read, total_bytes_read = 0;

    // start reading value
    while(total_bytes_read < length)
    {

        data_node& dn = cache_.retrieve(bo.block_num, false);
        try
        {
        bytes_read = dn.read_at(bo, length - total_bytes_read, out_buffer);
        }
        catch (const std::exception& e)
        {
            SAFE_LOG_EXCEPTION("read_at call failed");
            throw;
        }
        cache_.done(bo.block_num, false);

        //increment read bytes and advance block offset
        total_bytes_read += bytes_read;
        data_node::advance_block_offset(bo, bytes_read);
    }
}
