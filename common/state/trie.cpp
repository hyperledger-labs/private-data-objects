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

unsigned int pstate::trie_node::shared_prefix_length(
    const uint8_t* stored_chunk, size_t sc_length, const uint8_t* key_chunk, size_t kc_length)
{
    unsigned int spl = 0;
    while (spl < sc_length && spl < kc_length && stored_chunk[spl] == key_chunk[spl])
    {
        spl++;
    }
    return spl;
}

void pstate::trie_node::delete_trie_node_childless(data_node_io& dn_io,
    trie_node& node)
{
    block_offset bo_child(node.node.child_offset);
    if(bo_child.is_empty())
    {
        //release space of trie node
        dn_io.free_space_collector_.collect(node.location.block_offset_, trie_node::new_trie_node_size());

        // mark node as deleted
        node.node.hdr.isDeleted = 1;
        node.modified = true;

        //TRICK: write immediately the deleted node and update its location to be its next offset;
        //       this allows previous/upper node to correctly update their next/child offset
        write_trie_node(dn_io, node);
        node.location.block_offset_ = node.node.next_offset;
    }
}

void pstate::trie_node::do_write_value(data_node_io& dn_io,
    trie_node& node,
    const ByteArray& value)
{
    {
        //if overwriting, delete the current value
        block_offset current_child_bo(node.node.child_offset);
        if (! current_child_bo.is_empty())
        {
            do_delete_value(dn_io, node);
        }
    }

    unsigned int space_required = sizeof(trie_node_header_t) + sizeof(size_t) + value.size();

    //grab the offset where data is going to be written
    if(! dn_io.free_space_collector_.allocate(space_required, node.node.child_offset))
    {
        //search for reusable space failed, so append value
        dn_io.block_offset_for_appending(node.node.child_offset);
    }

    //conservatively mark node as modified -- it would be unmodified only when the freed space is immediately reused
    node.modified = true;

    //initialize the cursor for the write
    block_offset_t bo = node.node.child_offset;

    // write trie node first
    ByteArray ba_trie_node(sizeof(trie_node_header_t), 0);
    trie_node_header_t* h = (trie_node_header_t*)ba_trie_node.data();
    *h = empty_trie_header;
    h->isValue = 1;
    dn_io.write_across_data_nodes(ba_trie_node, 0, bo);
    data_node::advance_block_offset(bo, ba_trie_node.size());
    space_required -= ba_trie_node.size();

    // write buffer size second
    size_t value_size = value.size();
    ByteArray ba_value_size(
        (uint8_t*)&value_size, (uint8_t*)&value_size + sizeof(size_t));
    dn_io.write_across_data_nodes(ba_value_size, 0, bo);
    data_node::advance_block_offset(bo, ba_value_size.size());
    space_required -= ba_value_size.size();

    // write value
    dn_io.write_across_data_nodes(value, 0, bo);
    space_required -= value.size();
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        space_required != 0, "space estimated does not match space written");
}

void pstate::trie_node::do_read_value_info(data_node_io& dn_io,
        block_offset_t& bo_at, ByteArray& ba_header, size_t& value_size)
{
    //read trie node header
    dn_io.read_across_data_nodes(bo_at, sizeof(trie_node_header_t), ba_header);
    data_node::advance_block_offset(bo_at, sizeof(trie_node_header_t));
    //check header
    trie_node_header_t* h = (trie_node_header_t*)ba_header.data();
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !h->isValue, "read value, header read is not for value");

    //read value size
    ByteArray ba_value_size;
    dn_io.read_across_data_nodes(bo_at, sizeof(size_t), ba_value_size);
    data_node::advance_block_offset(bo_at, sizeof(size_t));
    value_size = *((size_t*)ba_value_size.data());
}

void pstate::trie_node::do_read_value(
    data_node_io& dn_io, const trie_node& node, ByteArray& value)
{
    block_offset current_child_bo(node.node.child_offset);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        current_child_bo.is_empty(), "read value, value is absent");

    block_offset_t bo = current_child_bo.block_offset_;
    ByteArray ba_header;
    size_t value_size;

    //read value info
    do_read_value_info(dn_io, bo, ba_header, value_size);

    // read value
    unsigned int vs = value_size;
    try
    {
        value.reserve(vs);
    }
    catch (const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("no space for reading value");
        throw;
    }
    dn_io.read_across_data_nodes(bo, vs, value);
}

void pstate::trie_node::do_delete_value(data_node_io& dn_io, trie_node& node)
{
    block_offset_t bo = node.node.child_offset;
    ByteArray ba_header;
    size_t value_size;

    //read value info
    do_read_value_info(dn_io, bo, ba_header, value_size);

    // mark trie node header (1 byte) as deleted
    trie_node_header_t* h = (trie_node_header_t*)(ba_header.data());
    h->isDeleted = 1;

    //overwrite stored header
    dn_io.write_across_data_nodes(ba_header, 0, bo);

    //recover space
    unsigned int freed_bytes = ba_header.size() + sizeof(value_size) + value_size;
    dn_io.free_space_collector_.collect(node.node.child_offset, freed_bytes);

    //delete value from trie
    node.node.child_offset = empty_block_offset;
    node.modified = true;
}

void pstate::trie_node::do_split_trie_node(
    data_node_io& dn_io, trie_node& node, unsigned int spl)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !(node.node.hdr.keyChunkSize > 0 && spl < node.node.hdr.keyChunkSize),
        "split node, wrong key chunk size and/or spl");
    dn_io.consume_add_and_init_append_data_node_cond(
        trie_node::new_trie_node_size() > dn_io.append_dn_->free_bytes());

    ByteArray second_chunk(
        node.node.key_chunk + spl, node.node.key_chunk + node.node.hdr.keyChunkSize);

    // make new node with second part of key chunk and same child offset and no next offset
    trie_node second_node;
    create_node(second_chunk, 0, second_chunk.size(), second_node);
    // adjust second node
    second_node.node.next_offset = empty_block_offset;
    second_node.node.child_offset = node.node.child_offset;
    second_node.modified = true;
    // write second node
    write_trie_node(dn_io, second_node);

    // adjust first (i.e., original) header, with original next offset, and new node as child
    node.node.hdr.keyChunkSize = spl;
    node.node.child_offset = second_node.location.block_offset_;
    node.modified = true;
}

size_t pstate::trie_node::new_trie_node_size()
{
    return sizeof(trie_node_h_with_nc_t) + MAX_KEY_CHUNK_BYTE_SIZE;
}

void pstate::trie_node::create_node(const ByteArray& key, unsigned int keyChunkBegin, unsigned int keyChunkEnd, trie_node& out_node)
{
    out_node.node.hdr.hasNext = 1;
    out_node.node.hdr.hasChild = 1;
    out_node.node.next_offset = empty_block_offset;
    out_node.node.child_offset = empty_block_offset;
    // compute key chunk length that can be copied
    size_t kcl = keyChunkEnd - keyChunkBegin;
    // recall that returnHeader->keyChunkSize has limits
    out_node.node.hdr.keyChunkSize = (kcl > MAX_KEY_CHUNK_BYTE_SIZE ? MAX_KEY_CHUNK_BYTE_SIZE : kcl);
    // copy only what can be written, aligned at the beginning of key chunk
    std::copy(key.begin() + keyChunkBegin, key.begin() + keyChunkBegin + out_node.node.hdr.keyChunkSize,
        out_node.node.key_chunk);

    //it is a new node, so mark it as modified to be later written
    out_node.modified = true;

    out_node.initialized = true;
}

void pstate::trie_node::read_trie_node(data_node_io& dn_io, block_offset_t& in_block_offset, trie_node& out_trie_node)
{
    ByteArray ba_node;
    dn_io.read_across_data_nodes(in_block_offset, sizeof(trie_node_h_with_ncc_t), ba_node);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        ba_node.size() != sizeof(trie_node_h_with_ncc_t), "unable to read trie node");

    //copy the node in the structure
    out_trie_node.node = *((trie_node_h_with_ncc_t*)ba_node.data());
    out_trie_node.location.block_offset_ = in_block_offset;
    out_trie_node.modified = false;
    out_trie_node.initialized = true;
}

void pstate::trie_node::write_trie_node(data_node_io& dn_io, trie_node& in_trie_node)
{
    // conventions:
    //  1. write to the same location (if available), otherwhise
    //  2. reuse free space (if possible), otherwise
    //  3. append

    if(in_trie_node.location.is_empty())
    {
        if(! dn_io.free_space_collector_.allocate(new_trie_node_size(), in_trie_node.location.block_offset_))
        {
            //search for reusable space failed, so append value
            dn_io.block_offset_for_appending(in_trie_node.location.block_offset_);
        }
    }

    ByteArray ba_node(sizeof(trie_node_h_with_ncc_t), 0);
    *((trie_node_h_with_ncc_t*)ba_node.data()) = in_trie_node.node;
    //write node
    dn_io.write_across_data_nodes(ba_node, 0, in_trie_node.location.block_offset_);
    in_trie_node.modified = false;
}

void pstate::trie_node::init_trie_root(data_node_io& dn_io)
{
    //initialize root node
    trie_node root;
    root.location.block_offset_ = {dn_io.block_warehouse_.get_root_block_num(), data_node::data_begin_index()};
    ByteArray emptyKey;
    create_node(emptyKey, 0, 0, root);

    //store root node
    write_trie_node(dn_io, root);
}

namespace pdo
{
namespace state
{
    class recursive_item
    {
    public:
        trie_node node;
        bool go_next; // true: proceed with next offset; false: proceed with child offset
    };
}
}

void pstate::trie_node::operate_trie_non_recursive(
    data_node_io& dn_io, const kv_operation_e operation, const ByteArray& kvkey, const ByteArray& in_value, ByteArray& out_value)
{
    std::list<recursive_item> trie_recursion_stack;
    unsigned int depth = 0;

    // the first entry of the first data node is the trie root
    // if the trie contains data then the root has a next node
    // if the trie is empty then the next node is null/empty
    recursive_item ri;
    ri.node.location.block_offset_ = {dn_io.block_warehouse_.get_root_block_num(), data_node::data_begin_index()};
    trie_node::read_trie_node(dn_io, ri.node.location.block_offset_, ri.node);
    //initialize the recursion stack with the root node
    ri.go_next = true;
    trie_recursion_stack.push_back(ri);
    //append next uninitialized node
    trie_recursion_stack.emplace_back();
    recursive_item& ri_next = trie_recursion_stack.back();
    ri_next.node.location.block_offset_ = ri.node.node.next_offset;

    while(1)
    {
        // reference to last item in stack
        // notice: the referenced node may not be initialized, it must be created if location is null,or read otherwise
        recursive_item& ri = trie_recursion_stack.back();

        // first, create/read the node if necessary, or return
        if(! ri.node.initialized)
        {
            if(ri.node.location.is_empty())
            {
                if (operation == PUT_OP)
                {
                    // in put operation, always create a trie node
                    create_node(kvkey, depth, kvkey.size(), ri.node);
                }
                else
                {
                    // no trie node to proceed with delete or get
                    return;
                }
            }
            else
            {
                //load the node
                read_trie_node(dn_io, ri.node.location.block_offset_, ri.node);
            }
        }

        // operate on trie node
        uint8_t* key_chunk_start_p = (uint8_t*)kvkey.data() + depth;
        unsigned int key_chunk_size = kvkey.size() - depth;
        unsigned int spl = shared_prefix_length(
                                (uint8_t*)ri.node.node.key_chunk,
                                ri.node.node.hdr.keyChunkSize,
                                key_chunk_start_p,
                                key_chunk_size);

        if (spl == 0)
        {  // no match, so either go next or EOS matched
            //if right depth has not been reached OR (it has been reached but) the current trie is not EOS, go next
            if (depth < kvkey.size() || ri.node.node.hdr.keyChunkSize > 0)
            {  // no match, go next
                //update field in referenced working recursive item
                ri.go_next = true;
                //push the next node with the location set (to avoid copy, append item and modify it)
                trie_recursion_stack.emplace_back();
                recursive_item& ri_next = trie_recursion_stack.back();
                ri_next.node.location.block_offset_ = ri.node.node.next_offset;
                //notice: depth value is not changed

                continue;
            }
            else
            {  // match EOS, do op
                switch (operation)
                {
                    case PUT_OP:
                    {
                        do_write_value(dn_io, ri.node, in_value);
                        break;
                    }
                    case GET_OP:
                    {
                        do_read_value(dn_io, ri.node, out_value);
                        break;
                    }
                    case DEL_OP:
                    {
                        do_delete_value(dn_io, ri.node);
                        break;
                    }
                    default:
                    {
                        throw error::ValueError("invalid kv/trie operation");
                    }
                }

                //operation done, exit the main while loop
                break;
            }
        }
        else
        {  // some match, so either partial or full
            if (spl == ri.node.node.hdr.keyChunkSize)
            {  // full match, go to child
                //update field in referenced working recursive item
                ri.go_next = false;
                //push the child node with the location set
                trie_recursion_stack.emplace_back();
                recursive_item& ri_child = trie_recursion_stack.back();
                ri_child.node.location.block_offset_ = ri.node.node.child_offset;
                //update depth value
                depth += spl;
            }
            else
            {  // partial match, continue only on PUT op
                if (operation == PUT_OP)
                {
                    // split chunk and redo operate
                    do_split_trie_node(dn_io, ri.node, spl);
                }
                else
                {
                    return;
                }
            }
            continue;
        }
    }

    // operation has been perfomed, now go bottom up emptying the recursion stack

    while(!trie_recursion_stack.empty())
    {
        // pop last item in stack
        recursive_item ri_popped = trie_recursion_stack.back();
        trie_recursion_stack.pop_back();

        if (operation == DEL_OP && trie_recursion_stack.size() > 1)
        {
            // check whether we should delete this trie node, while removing items from stack
            // as nodes have been deleted, childless nodes can be removed (except the root node)
            delete_trie_node_childless(dn_io, ri_popped.node);
        }

        if(ri_popped.node.modified)
        {
            write_trie_node(dn_io, ri_popped.node);
        }

        if(trie_recursion_stack.empty())
        {
            //no previous node to update
            continue;
        }

        // update offsets as necessary
        recursive_item& ri_prev = trie_recursion_stack.back();

        if(ri_prev.go_next)
        {
            //ri_popped is "next" of ri_prev
            //if next node location has changed, updated it
            if(ri_prev.node.node.next_offset != ri_popped.node.location.block_offset_)
            {
                ri_prev.node.node.next_offset = ri_popped.node.location.block_offset_;
                ri_prev.node.modified = true;
            }
        }
        else
        {
            //ri_popped is "child" of ri_prev
            //if child node location has changed, updated it
            if(ri_prev.node.node.child_offset != ri_popped.node.location.block_offset_)
            {
                ri_prev.node.node.child_offset = ri_popped.node.location.block_offset_;
                ri_prev.node.modified = true;
            }
        }

        continue;
    }
}
