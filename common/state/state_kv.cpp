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

#include <algorithm>
#include "parson.h"
#include "state.h"

#if _UNTRUSTED_
#define THROW_EXCEPTION_ON_STACK_FULL(p)
#else
extern "C" {
bool is_stack_addr(void* p, size_t size);
}

#define FAILURE_STACK_ZONE_BYTES 0x3000

#define THROW_EXCEPTION_ON_STACK_FULL(p)                               \
    {                                                                  \
        if (!is_stack_addr((uint8_t*)p - FAILURE_STACK_ZONE_BYTES, 1)) \
        {                                                              \
            throw pdo::error::RuntimeError("stack full");              \
        }                                                              \
    }
#endif

namespace pstate = pdo::state;

bool pstate::operator==(const block_offset_t& lhs, const block_offset_t& rhs)
{
    return (lhs.block_num == rhs.block_num && lhs.bytes == rhs.bytes);
}

bool pstate::operator!=(const block_offset_t& lhs, const block_offset_t& rhs)
{
    return !(lhs == rhs);
}

unsigned int pstate::block_offset::offset_size()
{
    return sizeof(block_offset_t);
}

unsigned int pstate::block_offset::serialized_offset_to_block_num(
    const ByteArray& serialized_offset)
{
    block_offset_t* p = (block_offset_t*)serialized_offset.data();
    return p->block_num;
}

unsigned int pstate::block_offset::serialized_offset_to_bytes(const ByteArray& serialized_offset)
{
    block_offset_t* p = (block_offset_t*)serialized_offset.data();
    return p->bytes;
}

ByteArray pstate::block_offset::to_ByteArray(const block_offset_t bo)
{
    uint8_t* p = (uint8_t*)&bo;
    return ByteArray(p, p + sizeof(block_offset_t));
}

void pstate::block_offset::serialize_offset(ByteArray& outBuffer)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        outBuffer.size() < offset_size(), "serialize, short buf");
    block_offset_t* p = (block_offset_t*)outBuffer.data();
    *p = block_offset_;
}

void pstate::block_offset::deserialize_offset(const ByteArray& inBuffer)
{
    block_offset_t* p = (block_offset_t*)inBuffer.data();
    block_offset_ = *p;
}

void pstate::block_offset::deserialize_offset(const block_offset_t bo)
{
    block_offset_ = bo;
}

void pstate::block_offset::empty()
{
    block_offset_ = empty_block_offset;
}

bool pstate::block_offset::is_empty()
{
    return (block_offset_ == empty_block_offset);
}

ByteArray pstate::block_offset::to_ByteArray()
{
    ByteArray b(sizeof(block_offset_t));
    serialize_offset(b);
    return b;
}

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

    //if(free_space_collection.size() > max number of items)
    //{
    //  TODO trigger kv compaction
    //}

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

void pstate::trie_node::do_operate_trie_child(data_node_io& dn_io,
    trie_node& node,
    const kv_operation_e operation,
    const unsigned int depth,
    const ByteArray& kvkey,
    const ByteArray& in_value,
    ByteArray& value)
{
    trie_node child_node;
    child_node.location.block_offset_ = node.node.child_offset;

    // operate on child node
    operate_trie(dn_io, child_node, operation,
        depth + node.node.hdr.keyChunkSize,  // all key chunk was matched
        kvkey, in_value, value);

    //if child node location has changed, updated it
    if(node.node.child_offset != child_node.location.block_offset_)
    {
        node.node.child_offset = child_node.location.block_offset_;
        node.modified = true;
    }
}

void pstate::trie_node::do_operate_trie_next(data_node_io& dn_io,
    trie_node& node,
    const kv_operation_e operation,
    const unsigned int depth,
    const ByteArray& kvkey,
    const ByteArray& in_value,
    ByteArray& value)
{
    trie_node next_node;
    next_node.location.block_offset_ = node.node.next_offset;

    // operate on next node
    operate_trie(dn_io, next_node, operation,
        depth,  // same depth
        kvkey, in_value, value);

    //if next node location has changed, updated it
    if(node.node.next_offset != next_node.location.block_offset_)
    {
        node.node.next_offset = next_node.location.block_offset_;
        node.modified = true;
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

void pstate::trie_node::operate_trie(data_node_io& dn_io,
    trie_node& node,
    const kv_operation_e operation,
    const unsigned int depth,
    const ByteArray& kvkey,
    const ByteArray& in_value,
    ByteArray& out_value)
{
#if !_UNTRUSTED_
    int stack_check_var;
    THROW_EXCEPTION_ON_STACK_FULL(&stack_check_var)
#endif

    // first, create the node if necessary, or fail
    if(! node.initialized)
    {
        if(node.location.is_empty())
        {
            if (operation == PUT_OP)
            {
                // in put operation, always create a trie node
                create_node(kvkey, depth, kvkey.size(), node);
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
            read_trie_node(dn_io, node.location.block_offset_, node);
        }
    }

    // operate on trie node
    unsigned int spl = shared_prefix_length((uint8_t*)node.node.key_chunk, node.node.hdr.keyChunkSize,
        kvkey.data() + depth, kvkey.size() - depth);

    if (spl == 0)
    {  // no match, so either go next or EOS matched
        //if right depth has not been reached OR (it has been reached but) the current trie is not EOS, go next
        if (depth < kvkey.size() || node.node.hdr.keyChunkSize > 0)
        {  // no match, go next
            do_operate_trie_next(
                dn_io, node, operation, depth, kvkey, in_value, out_value);
        }
        else
        {  // match EOS, do op
            switch (operation)
            {
                case PUT_OP:
                {
                    do_write_value(dn_io, node, in_value);
                    break;
                }
                case GET_OP:
                {
                    do_read_value(dn_io, node, out_value);
                    break;
                }
                case DEL_OP:
                {
                    do_delete_value(dn_io, node);
                    break;
                }
                default:
                {
                    throw error::ValueError("invalid kv/trie operation");
                }
            }
        }
    }
    else
    {  // some match, so either partial or full
        if (spl == node.node.hdr.keyChunkSize)
        {  // full match
            do_operate_trie_child(
                dn_io, node, operation, depth, kvkey, in_value, out_value);
        }
        else
        {  // partial match, continue only on PUT op
            if (operation == PUT_OP)
            {
                // split chunk and redo operate
                do_split_trie_node(dn_io, node, spl);

                // notice: current_tnh remains the same because: 1) chunk is just shorter; 2) its
                // next (if any) is removed; 3) it had and keeps having a child

                operate_trie(dn_io, node, operation, depth, kvkey, in_value, out_value);
            }
        }
    }

    if (operation == DEL_OP)
    {
        // check whether we should delete this trie node, while going bottom up
        delete_trie_node_childless(dn_io, node);
    }

    if(node.modified)
    {
        write_trie_node(dn_io, node);
    }
}  // operate_trie

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

void pstate::trie_node::operate_trie_root(
    data_node_io& dn_io, const kv_operation_e operation, const ByteArray& kvkey, const ByteArray& in_value, ByteArray& value)
{
    unsigned int depth = 0;
    // the first entry of the first data node is the trie root
    // if the trie contains data then the root has a next node
    // if the trie is empty then the next node is null/empty
    trie_node root;
    root.location.block_offset_ = {dn_io.block_warehouse_.get_root_block_num(), data_node::data_begin_index()};
    trie_node::read_trie_node(dn_io, root.location.block_offset_, root);

    do_operate_trie_next(dn_io, root, operation, depth, kvkey, in_value, value);

    // check modifications
    if(root.modified)
    {
        write_trie_node(dn_io, root);
    }
    // NOTICE: we do NOT sync the cache here, so modifications are not reflected in the block store;
    //         in the case of failure, any modification is discarded, the transaction in progress will not succeed,
    //         no new state is generated, and the request processing can (and will) start over from the last state
}

ByteArray pstate::data_node::make_offset(unsigned int block_num, unsigned int bytes_off)
{
    try
    {
        ByteArray ba_block_num((uint8_t*)&block_num, (uint8_t*)&block_num + sizeof(block_num));
        ByteArray ba_off_from_start((uint8_t*)&bytes_off, (uint8_t*)&bytes_off + sizeof(bytes_off));
        // concatenate the two values
        ba_block_num.insert(ba_block_num.end(), ba_off_from_start.begin(), ba_off_from_start.end());
        return ba_block_num;
    }
    catch(const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("make offset error");
        throw;
    }
}

pstate::data_node::data_node(unsigned int block_num) : data_(FIXED_DATA_NODE_BYTE_SIZE)
{
    block_num_ = block_num;
    data_.resize(data_end_index());
    free_bytes_ = data_end_index() - data_begin_index();
}

unsigned int pstate::data_node::data_begin_index()
{
    return sizeof(unsigned int) + sizeof(unsigned int);
}

unsigned int pstate::data_node::data_end_index()
{
    return FIXED_DATA_NODE_BYTE_SIZE;
}

unsigned int pstate::data_node::get_block_num()
{
    return block_num_;
}

void pstate::data_node::cursor(block_offset_t& out_bo)
{
    out_bo.block_num = block_num_;
    out_bo.bytes = data_end_index() - free_bytes_;
}

void pstate::data_node::serialize_data_header()
{
    ByteArray header = make_offset(block_num_, free_bytes_);
    std::copy(header.begin(), header.end(), data_.begin());
}

void pstate::data_node::decrypt_and_deserialize_data(
    const ByteArray& inEncryptedData, const ByteArray& state_encryption_key)
{
    data_ = pdo::crypto::skenc::DecryptMessage(state_encryption_key, inEncryptedData);
    block_num_ = block_offset::serialized_offset_to_block_num(data_);
    free_bytes_ = block_offset::serialized_offset_to_bytes(data_);
}

void pstate::data_node::deserialize_original_encrypted_data_id(StateBlockId& id)
{
    originalEncryptedDataNodeId_ = id;
}

unsigned int pstate::data_node::free_bytes()
{
    return free_bytes_;
}

void pstate::data_node::consume_free_space(unsigned int length)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        length > free_bytes_, "cannot consume more bytes than available free space");
    free_bytes_ -= length;
}

void pstate::data_node::advance_block_offset(block_offset_t& bo, unsigned int length)
{
    unsigned int block_data_len = pstate::data_node::data_end_index() - pstate::data_node::data_begin_index();
    //advance as many blocks a possible
    unsigned int blocks_to_add = length / block_data_len;
    bo.block_num += blocks_to_add;
    length -= (blocks_to_add * block_data_len);
    //advance the bytes field
    bo.bytes += length;
    //correct the bo in case of overflow
    if(bo.bytes >= pstate::data_node::data_end_index()) //if equal, there is no overflow, but need switch to next block
    {
        bo.block_num +=1;
        bo.bytes = pstate::data_node::data_begin_index() + (bo.bytes - pstate::data_node::data_end_index());
    }
}

unsigned int pstate::data_node::write_at(const ByteArray& buffer, unsigned int write_from, const block_offset_t& bo_at)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        block_num_ != bo_at.block_num, "write, bad block num");
    unsigned int cursor = bo_at.bytes;
    unsigned int buffer_size = buffer.size() - write_from;
    unsigned int writeable_bytes = data_end_index() - cursor;

    // write as much buffer as possible: either all buffer or until block boundary
    unsigned int bytes_to_write = (buffer_size <= writeable_bytes ? buffer_size : writeable_bytes);
    std::copy(buffer.begin() + write_from, buffer.begin() + write_from + bytes_to_write,
        data_.begin() + cursor);
    cursor += bytes_to_write;

    //consume free bytes if necessary
    unsigned int old_cursor = data_end_index() - free_bytes_;
    free_bytes_ = (old_cursor <= cursor ? data_end_index() - cursor : free_bytes_);

    return bytes_to_write;
}

unsigned int pstate::data_node::read_at(const block_offset_t& bo_at, unsigned int bytes, ByteArray& outBuffer)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        block_num_ != bo_at.block_num, "read, bad block num");

    // read as much as possible in outbuffer
    unsigned int bytes_to_endof_data = data_end_index() - bo_at.bytes;
    unsigned int bytes_to_read =
        (bytes <= bytes_to_endof_data ? bytes : bytes_to_endof_data);

    try
    {
    outBuffer.insert(
        outBuffer.end(),
        data_.begin() + bo_at.bytes,
        data_.begin() + bo_at.bytes + bytes_to_read);
    }
    catch (const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("value read");
        throw;
    }

    //return bytes read
    return bytes_to_read;
}

void pstate::data_node::load(const ByteArray& state_encryption_key)
{
    state_status_t ret;
    ByteArray encrypted_buffer;
    ret = sebio_fetch(originalEncryptedDataNodeId_, SEBIO_NO_CRYPTO, encrypted_buffer);
    pdo::error::ThrowIf<pdo::error::ValueError>(ret != STATE_SUCCESS,
        ("data node load, sebio returned an error-" +
            ByteArrayToHexEncodedString(originalEncryptedDataNodeId_))
            .c_str());
    decrypt_and_deserialize_data(encrypted_buffer, state_encryption_key);
}

void pstate::data_node::unload(
    const ByteArray& state_encryption_key, StateBlockId& outEncryptedDataNodeId)
{
    serialize_data_header();
    ByteArray baEncryptedData = pdo::crypto::skenc::EncryptMessage(state_encryption_key, data_);
    state_status_t ret =
        sebio_evict(baEncryptedData, SEBIO_NO_CRYPTO, originalEncryptedDataNodeId_);
    pdo::error::ThrowIf<pdo::error::ValueError>(
        ret != STATE_SUCCESS, "data node unload, sebio returned an error");
    // return new id
    outEncryptedDataNodeId = originalEncryptedDataNodeId_;
}

void pstate::data_node_io::block_offset_for_appending(block_offset_t& out_bo)
{
    //bring in new node if necessary
    consume_add_and_init_append_data_node_cond(append_dn_->free_bytes() == 0);

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
        true);  // nobody is using it now; new nodes are modified
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
    free_space_collector_.collect(bo, append_dn_->free_bytes());
    append_dn_->consume_free_space(append_dn_->free_bytes());

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
        data_node& dn = cache_.retrieve(bo.block_num, false);
        bytes_written = dn.write_at(buffer, total_bytes_written, bo);
        cache_.done(bo.block_num, true);

        //increment written bytes and advance block offset
        total_bytes_written += bytes_written;
        data_node::advance_block_offset(bo, bytes_written);

        //if we are appending and the block offset touches a new data node, make sure to append a new one to the list
        add_and_init_append_data_node_cond(bo.block_num > block_warehouse_.get_last_block_num());
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
        cache_.done(bo.block_num, true);

        //increment read bytes and advance block offset
        total_bytes_read += bytes_read;
        data_node::advance_block_offset(bo, bytes_read);
    }
}

void pdo::state::block_warehouse::serialize_block_ids(pdo::state::StateNode& node)
{
    node.ClearChildren();
    for (unsigned int i = 0; i < blockIds_.size(); i++)
    {
        node.AppendChildId(blockIds_[i]);
    }
    node.BlockifyChildren();
}

void pdo::state::block_warehouse::deserialize_block_ids(pdo::state::StateNode& node)
{
    node.UnBlockifyChildren();
    blockIds_ = node.GetChildrenBlocks();
}

void pdo::state::block_warehouse::update_datablock_id(
    unsigned int data_block_num, pdo::state::StateBlockId& newId)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        newId.size() != STATE_BLOCK_ID_LENGTH, "bad block id");

    unsigned int index = data_block_num;
    blockIds_[index] = newId;
}

void pdo::state::block_warehouse::add_block_id(pstate::StateBlockId& id)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        id.size() != STATE_BLOCK_ID_LENGTH, "bad block id");

    try
    {
        blockIds_.push_back(id);
    }
    catch (const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("block_warehouse::add_block_id");
        throw;
    }
}

void pdo::state::block_warehouse::remove_empty_block_ids()
{
    StateBlockId emptyId(STATE_BLOCK_ID_LENGTH, 0);
    unsigned int i = 0;
    while (i < blockIds_.size())
    {
        if (blockIds_[i] == emptyId)
        {
            blockIds_.erase(blockIds_.begin() + i);
        }
        else
            i++;
    }
}

void pdo::state::block_warehouse::remove_block_id_from_datablock_num(unsigned int data_block_num)
{
    unsigned int index = data_block_num;
    blockIds_.erase(blockIds_.begin() + index);
}

void pdo::state::block_warehouse::get_datablock_id_from_datablock_num(
    unsigned int data_block_num, pdo::state::StateBlockId& outId)
{
    // CONVENTION:  the data blocks are put in sequential order in the list,
    //              where the last block is the last appended data block
    unsigned int index = data_block_num;
    outId = blockIds_[index];
}

unsigned int pdo::state::block_warehouse::get_root_block_num()
{
    return 0;  // convention
}

unsigned int pdo::state::block_warehouse::get_last_block_num()
{
    return blockIds_.size() - 1;
}

pdo::state::State_KV::State_KV(const ByteArray& key)
    : state_encryption_key_(key), dn_io_(data_node_io(key))
{
    try
    {
        // initialize first data node
        data_node dn(dn_io_.block_warehouse_.get_root_block_num());
        StateBlockId dn_id;
        dn.unload(state_encryption_key_, dn_id);
        dn_io_.block_warehouse_.add_block_id(dn_id);

        // cache and pin first data node
        dn_io_.init_append_data_node();

        // init trie root node in first data node
        trie_node::init_trie_root(dn_io_);

        // pin in cache the first one
        dn_io_.cache_.pin(dn_io_.block_warehouse_.get_root_block_num());
    }
    catch(const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("create kv error");
        throw;
    }

    kv_start_mode = KV_CREATE;
}

pdo::state::State_KV::State_KV(const StateBlockId& id, const ByteArray& key)
    : state_encryption_key_(key), dn_io_(data_node_io(key))
{
    try
    {
        // retrieve main state block, root node and last data node
        rootNode_.GetBlockId() = id;
        state_status_t ret;
        ret = sebio_fetch(id, SEBIO_NO_CRYPTO, rootNode_.GetBlock());
        pdo::error::ThrowIf<pdo::error::ValueError>(
            ret != STATE_SUCCESS, "statekv::init, sebio returned an error");

        dn_io_.initialize(rootNode_);
    }
    catch(const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("open kv error");
        throw;
    }

    kv_start_mode = KV_OPEN;
}

void pdo::state::State_KV::Finalize(ByteArray& outId)
{
    try
    {
        //store the free space collection table IF the kv has been create OR the table has been modified
        if(kv_start_mode == KV_CREATE || dn_io_.free_space_collector_.collection_modified())
        {
            //serialize free space collection table and store it in one data node
            dn_io_.add_and_init_append_data_node();
            dn_io_.free_space_collector_.serialize_in_data_node(*dn_io_.append_dn_);
        }
        else
        {
            // collection table not modified, simply put its original block id in the list
            dn_io_.block_warehouse_.add_block_id(dn_io_.free_space_collector_.original_block_id_of_collection);
        }

        // flush cache first
        dn_io_.cache_.flush();

        // serialize block ids
        dn_io_.block_warehouse_.serialize_block_ids(rootNode_);

        // evict root block
        ByteArray baBlock = rootNode_.GetBlock();
        state_status_t ret = sebio_evict(baBlock, SEBIO_NO_CRYPTO, rootNode_.GetBlockId());
        pdo::error::ThrowIf<pdo::error::ValueError>(
            ret != STATE_SUCCESS, "kv root node unload, sebio returned an error");

        // output the root id
        outId = rootNode_.GetBlockId();
    }
    catch(const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("finalize kv error");
        throw;
    }
}

ByteArray pstate::State_KV::Get(const ByteArray& key)
{
    // perform operation
    const ByteArray& kvkey = key;
    const ByteArray in_value;
    ByteArray out_value;
    try
    {
        trie_node::operate_trie_root(dn_io_, GET_OP, kvkey, in_value, out_value);
    }
    catch(const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("kv get error");
        throw;
    }
    return out_value;
}

void pstate::State_KV::Put(const ByteArray& key, const ByteArray& value)
{
    // perform operation
    const ByteArray& kvkey = key;
    ByteArray v;
    try
    {
        trie_node::operate_trie_root(dn_io_, PUT_OP, kvkey, value, v);
    }
    catch (const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("kv put error");
        throw;
    }
}

void pstate::State_KV::Delete(const ByteArray& key)
{
    // perform operation
    const ByteArray in_value;
    ByteArray value;
    const ByteArray& kvkey = key;
    try
    {
        trie_node::operate_trie_root(dn_io_, DEL_OP, kvkey, in_value, value);
    }
    catch(const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("kv delete error");
        throw;
    }
}
