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
#include "c11_support.h"
#include "crypto.h"
#include "error.h"
#include "jsonvalue.h"
#include "log.h"
#include "packages/base64/base64.h"
#include "parson.h"
#include "pdo_error.h"
#include "state.h"
#include "types.h"

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

#define FIXED_DATA_NODE_BYTE_SIZE (1 << 13)  // 8 KB
#define CACHE_SIZE (1 << 22)                 // 4 MB
#define BLOCK_CACHE_MAX_ITEMS (CACHE_SIZE / FIXED_DATA_NODE_BYTE_SIZE)

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

pstate::cache_slots::cache_slots() : data_nodes_(BLOCK_CACHE_MAX_ITEMS, data_node(0))
{
    for (unsigned int i = 0; i < data_nodes_.size(); i++)
    {
        dn_queue_.push(&(data_nodes_[i]));
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
    dn_queue_.push(*dn);
    // delete original pointer
    *dn = NULL;
}

pstate::block_offset_t* pstate::trie_node::goto_next_offset(trie_node_header_t* header)
{
    if (header->hasNext)
    {
        trie_node_h_with_n_t* p = (trie_node_h_with_n_t*)header;
        return &(p->next_offset);
    }
    return NULL;
}

pstate::block_offset_t* pstate::trie_node::goto_child_offset(trie_node_header_t* header)
{
    if (header->hasNext)
    {
        if (header->hasChild)
        {
            trie_node_h_with_nc_t* p = (trie_node_h_with_nc_t*)header;
            return &(p->child_offset);
        }
        return NULL;
    }
    if (header->hasChild)
    {
        trie_node_h_with_c_t* p = (trie_node_h_with_c_t*)header;
        return &(p->child_offset);
    }
    return NULL;
}

uint8_t* pstate::trie_node::goto_key_chunk(trie_node_header_t* header)
{
    if (header->keyChunkSize == 0)
    {
        return NULL;
    }
    uint8_t* p = (uint8_t*)header;
    p += sizeof(trie_node_header_t);
    if (header->hasNext)
        p += sizeof(block_offset_t);
    if (header->hasChild)
        p += sizeof(block_offset_t);
    return p;
}

void pstate::trie_node::resize_key_chunk(trie_node_header_t* header, unsigned int new_size)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        header->keyChunkSize < new_size, "resize key chunk, new size is larger");
    uint8_t* p = goto_key_chunk(header);
    for (int i = new_size; i < header->keyChunkSize; i++)
        p[i] = *((uint8_t*)&deleted_trie_header);
    header->keyChunkSize = new_size;
}

void pstate::trie_node::delete_child_offset(trie_node_header_t* header)
{
    *goto_child_offset(header) = empty_block_offset;
}
void pstate::trie_node::delete_next_offset(trie_node_header_t* header)
{
    *goto_next_offset(header) = empty_block_offset;
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

void pstate::trie_node::delete_trie_node(trie_node_header_t* header)
{
    resize_key_chunk(header, 0);
    delete_child_offset(header);
    delete_next_offset(header);
    header->isDeleted = 1;
}

void pstate::trie_node::delete_trie_node_childless(
    trie_node_header_t* header, block_offset& out_bo_new)
{
    if (!header->hasChild || *goto_child_offset(header) == empty_block_offset)
    {
        // set new offset as next offset
        out_bo_new.block_offset_ = *goto_next_offset(header);
        // mark node as deleted
        delete_trie_node(header);
    }
}

void pstate::trie_node::update_trie_node_next(
    trie_node_header_t* header, block_offset_t* bo_next, block_offset& out_bo_new)
{
    trie_node_header_t* tnh = header;
    block_offset_t* bon = goto_next_offset(tnh);
    *bon = *bo_next;
}

void pstate::trie_node::update_trie_node_child(
    trie_node_header_t* header, block_offset_t* bo_child, block_offset& out_bo_new)
{
    trie_node_header_t* tnh = header;
    block_offset_t* boc = goto_child_offset(tnh);
    *boc = *bo_child;
}

void pstate::trie_node::do_operate_trie_child(data_node_io& dn_io,
    trie_node_header_t* trie_node_header,
    const kv_operation_e operation,
    const unsigned int depth,
    const ByteArray& kvkey,
    ByteArray& value,
    block_offset& outBlockOffset)
{
    block_offset current_child_bo;
    unsigned int cached_child_block_index;
    trie_node_header_t* child;

    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !trie_node_header->hasChild, "operate trie child expects a child node");

    // retrieve child node from cache (if it exists)
    current_child_bo.deserialize_offset(*goto_child_offset(trie_node_header));
    cached_child_block_index = current_child_bo.block_offset_.block_num;
    data_node& dn = dn_io.cache_retrieve(cached_child_block_index, false);
    if (current_child_bo.is_empty())
    {
        child = NULL;
    }
    else
    {
        child = (trie_node_header_t*)dn.offset_to_pointer(current_child_bo.to_ByteArray());
    }

    // operate on child node
    operate_trie(dn_io, child, operation,
        depth + trie_node_header->keyChunkSize,  // all key chunk was matched
        kvkey, value, current_child_bo);

    // if node modified, mark cached block as modified
    update_trie_node_child(trie_node_header, &current_child_bo.block_offset_, outBlockOffset);
    dn_io.cache_done(cached_child_block_index, false);  // keeps modified flag of operate_trie
}

void pstate::trie_node::do_operate_trie_next(data_node_io& dn_io,
    trie_node_header_t* trie_node_header,
    const kv_operation_e operation,
    const unsigned int depth,
    const ByteArray& kvkey,
    ByteArray& value,
    block_offset& outBlockOffset)
{
    // the trie node might not have a "next" node
    block_offset current_next_bo;
    trie_node_header_t* next;
    unsigned int cached_next_block_index = 0;

    // retrieve next node from cache (if it exists) -- i.e., cache the block of the next node
    current_next_bo.deserialize_offset(*goto_next_offset(trie_node_header));
    cached_next_block_index = current_next_bo.block_offset_.block_num;
    data_node& dn = dn_io.cache_retrieve(cached_next_block_index, false);
    if (current_next_bo.is_empty())
    {
        next = NULL;
    }
    else
    {
        next = (trie_node_header_t*)dn.offset_to_pointer(current_next_bo.to_ByteArray());
    }

    // operate on next node
    operate_trie(dn_io, next, operation,
        depth,  // same depth
        kvkey, value, current_next_bo);

    // if node modified, mark cached block as modified
    update_trie_node_next(trie_node_header, &current_next_bo.block_offset_, outBlockOffset);
    dn_io.cache_done(cached_next_block_index, false);  // keeps modified flag of operate_trie
}

void pstate::trie_node::do_write_value(data_node_io& dn_io,
    trie_node_header_t* header,
    const ByteArray& value,
    block_offset& outBlockOffset)
{
    unsigned int bytes_written, total_bytes_written = 0;
    ByteArray baOffset;
    // switch to an empty data node (if necessary)
    dn_io.add_and_init_append_data_node_cond(!dn_io.append_dn_->enough_space_for_value(false));

    // start writing value
    bytes_written = dn_io.append_dn_->write(value, total_bytes_written, baOffset);
    total_bytes_written += bytes_written;

    // update child with offset of initial write
    block_offset child_bo;
    child_bo.deserialize_offset(baOffset);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !header->hasChild, "write value, header must have been created with child");
    update_trie_node_child(header, &child_bo.block_offset_, outBlockOffset);

    // mark cache item as modified
    dn_io.cache_modified(child_bo.block_offset_.block_num);

    // keep writing if necessary
    while (total_bytes_written < value.size())
    {
        dn_io.add_and_init_append_data_node();
        bytes_written = dn_io.append_dn_->write(value, total_bytes_written, baOffset);
        total_bytes_written += bytes_written;
        pdo::error::ThrowIf<pdo::error::ValueError>(
            dn_io.append_dn_->enough_space_for_value(true) && total_bytes_written < value.size(),
            "operate, unwritten bytes while there is free space");
    }
}

void pstate::trie_node::do_read_value(
    data_node_io& dn_io, trie_node_header_t* trie_node_header, ByteArray& value)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !trie_node_header->hasChild, "read value, header must have child");
    block_offset current_child_bo;
    current_child_bo.deserialize_offset(*goto_child_offset(trie_node_header));
    if (current_child_bo.is_empty())
    {
        // value is absent
        return;
    }

    // read value
    unsigned int next_block_num = current_child_bo.block_offset_.block_num;
    bool first_read_done = false;
    unsigned int bytes_to_read = 0;
    while (1)
    {
        data_node& dn = dn_io.cache_retrieve(next_block_num, false);
        bytes_to_read =
            dn.read(current_child_bo.to_ByteArray(), value, first_read_done, bytes_to_read);
        dn_io.cache_done(next_block_num, false);
        first_read_done = true;
        next_block_num++;
        if (bytes_to_read == 0)
            break;
    }
}

void pstate::trie_node::do_delete(trie_node_header_t* header)
{
    delete_child_offset(header);
}

void pstate::trie_node::do_split_trie_node(
    data_node_io& dn_io, trie_node_header_t* header, unsigned int spl)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !(header->keyChunkSize > 0 && spl < header->keyChunkSize),
        "split node, wrong key chunk size and/or spl");
    dn_io.add_and_init_append_data_node_cond(
        trie_node::new_trie_node_size() > dn_io.append_dn_->free_bytes());

    ByteArray second_chunk(
        goto_key_chunk(header) + spl, goto_key_chunk(header) + header->keyChunkSize);

    // make new node with second part of key chunk and same child offset and no next offset
    ByteArray baSecondHeaderOffset;  // not important now
    trie_node_header_t* second_header = dn_io.append_dn_->write_trie_node(false,
        header->hasNext,   // same as original
        header->hasChild,  // same as original
        second_chunk, 0, second_chunk.size(), baSecondHeaderOffset);
    block_offset child_bo, next_bo, new_bo;

    // adjust second header
    update_trie_node_child(second_header, goto_child_offset(header), new_bo);
    delete_next_offset(second_header);

    // adjust first (i.e., original) header, with original next offset, and new node as child
    resize_key_chunk(header, spl);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !header->hasChild, "split node, header must have child");
    child_bo.deserialize_offset(baSecondHeaderOffset);
    update_trie_node_child(header, &child_bo.block_offset_, new_bo);
    // header pointer and its block_offset (unavailable here) remain unchanged
}

size_t pstate::trie_node::new_trie_node_size()
{
    return sizeof(trie_node_h_with_nc_t) + MAX_KEY_CHUNK_BYTE_SIZE;
}

pstate::trie_node_header_t* pstate::trie_node::append_trie_node(data_node_io& dn_io,
    const ByteArray& kvkey,
    const unsigned int key_begin,
    const unsigned int key_end,
    block_offset& outBlockOffset)
{
    ByteArray returnOffset;
    trie_node_header_t* new_tnh;

    dn_io.add_and_init_append_data_node_cond(new_trie_node_size() > dn_io.append_dn_->free_bytes());
    new_tnh = dn_io.append_dn_->write_trie_node(false,  // not deleted
        true,                                           // has next node
        true,                                           // has a child node
        kvkey,
        key_begin,  // add key chunk starting at depth
        key_end,    // end key chunk at key size
        returnOffset);
    outBlockOffset.deserialize_offset(returnOffset);
    return new_tnh;
}

void pstate::trie_node::operate_trie(data_node_io& dn_io,
    trie_node_header_t* trie_node_header,
    const kv_operation_e operation,
    const unsigned int depth,
    const ByteArray& kvkey,
    ByteArray& value,
    block_offset& outBlockOffset)
{
    trie_node_header_t* current_tnh;
    ByteArray returnOffset;
    unsigned int cur_thn_block_num;

#if !_UNTRUSTED_
    THROW_EXCEPTION_ON_STACK_FULL(&current_tnh)
#endif

    // first, create the node if necessary, or fail
    if (trie_node_header == NULL)
    {
        if (operation == PUT_OP)
        {
            // in put operation, always create a trie node
            current_tnh = append_trie_node(dn_io, kvkey, depth, kvkey.size(), outBlockOffset);
        }
        else
        {
            // no trie node to proceed with delete or get
            return;
        }
    }
    else
    {
        current_tnh = trie_node_header;
    }

    // ensure it remains cached
    cur_thn_block_num = outBlockOffset.block_offset_.block_num;
    dn_io.cache_retrieve(cur_thn_block_num, false);
    block_offset_t orig_next_bo = *goto_next_offset(current_tnh);
    block_offset_t orig_child_bo = *goto_child_offset(current_tnh);

    // operate on trie node
    unsigned int spl = shared_prefix_length(goto_key_chunk(current_tnh), current_tnh->keyChunkSize,
        kvkey.data() + depth, kvkey.size() - depth);

    if (spl == 0)
    {  // no match, so either go next or EOS matched
        if (depth < kvkey.size())
        {  // no match, go next
            do_operate_trie_next(
                dn_io, current_tnh, operation, depth, kvkey, value, outBlockOffset);
        }
        else
        {  // match EOS, do op
            switch (operation)
            {
                case PUT_OP:
                {
                    do_write_value(dn_io, current_tnh, value, outBlockOffset);
                    break;
                }
                case GET_OP:
                {
                    do_read_value(dn_io, current_tnh, value);
                    break;
                }
                case DEL_OP:
                {
                    do_delete(current_tnh);
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
        if (spl == current_tnh->keyChunkSize)
        {  // full match
            do_operate_trie_child(
                dn_io, current_tnh, operation, depth, kvkey, value, outBlockOffset);
        }
        else
        {  // partial match, continue only on PUT op
            if (operation == PUT_OP)
            {
                // split chunk and redo operate
                do_split_trie_node(dn_io, current_tnh, spl);
                // notice: current_tnh remains the same because: 1) chunk is just shorter; 2) its
                // next
                //         (if any) is removed; 3) it had and keeps having a child
                operate_trie(dn_io, current_tnh, operation, depth, kvkey, value, outBlockOffset);
            }
        }
    }

    if (operation == DEL_OP)
    {
        // check whether we should delete this trie node, while going bottom up
        delete_trie_node_childless(current_tnh, outBlockOffset);
    }
    // the cached block of currentnh can be released -- the modified field maintains previous
    // updates
    bool cache_modified = (orig_next_bo != *goto_next_offset(current_tnh) ||
                           orig_child_bo != *goto_child_offset(current_tnh));
    dn_io.cache_done(cur_thn_block_num, cache_modified);
}  // operate_trie

void pstate::trie_node::init_trie_root(data_node_io& dn_io)
{
    ByteArray retOffset;
    ByteArray emptyKey;
    block_offset_t expected_block_offset = {
        0, FIXED_DATA_NODE_BYTE_SIZE - dn_io.append_dn_->free_bytes()};
    dn_io.append_dn_->write_trie_node(false, true, true, emptyKey, 0, 0, retOffset);
    // check
    block_offset bo;
    bo.deserialize_offset(retOffset);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !(expected_block_offset == bo.block_offset_), "unexpected block offset for trie root");
}

void pstate::trie_node::operate_trie_root(
    data_node_io& dn_io, const kv_operation_e operation, const ByteArray& kvkey, ByteArray& value)
{
    unsigned int depth = 0;
    // the first entry of the first data node is the trie root
    // if the trie contains data then the root has a next node
    // if the trie is empty then the next node is null/empty
    unsigned int root_block_num = dn_io.block_warehouse_.get_root_block_num();
    data_node& dn = dn_io.cache_retrieve(root_block_num, true);  // get first data node
    // get pointer to trie root
    block_offset root_bo;
    root_bo.block_offset_ = {root_block_num, block_offset::offset_size()};
    ByteArray ba_serialized_offset;
    ba_serialized_offset.resize(block_offset::offset_size());
    root_bo.serialize_offset(ba_serialized_offset);
    trie_node_header_t* trie_root = (trie_node_header_t*)dn.offset_to_pointer(ba_serialized_offset);
    // save next offset to check for modifications
    block_offset_t bo_next_prev = *goto_next_offset(trie_root);

    do_operate_trie_next(dn_io, trie_root, operation, depth, kvkey, value, root_bo);

    // check modifications
    bool current_tnh_modified = !(bo_next_prev == *goto_next_offset(trie_root));
    // release block in cache
    dn_io.cache_done(root_block_num, current_tnh_modified);

    // NOTICE: we do NOT sync the cache here, so modifications are not reflected in the block store;
    //         in the case of failure, any modification is discarded, the transaction in progress will not succeed,
    //         no new state is generated, and the request processing can (and will) start over from the last state
}

ByteArray pstate::data_node::make_offset(unsigned int block_num, unsigned int bytes_off)
{
    ByteArray ba_block_num((uint8_t*)&block_num, (uint8_t*)&block_num + sizeof(block_num));
    ByteArray ba_off_from_start((uint8_t*)&bytes_off, (uint8_t*)&bytes_off + sizeof(bytes_off));
    // concatenate the two values
    ba_block_num.insert(ba_block_num.end(), ba_off_from_start.begin(), ba_off_from_start.end());
    return ba_block_num;
}

pstate::data_node::data_node(unsigned int block_num) : data_(FIXED_DATA_NODE_BYTE_SIZE)
{
    block_num_ = block_num;
    free_bytes_ = FIXED_DATA_NODE_BYTE_SIZE - sizeof(unsigned int) - sizeof(unsigned int);
    data_.resize(FIXED_DATA_NODE_BYTE_SIZE);
}

unsigned int pstate::data_node::get_block_num()
{
    return block_num_;
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

void pstate::data_node::deserialize_data(const ByteArray& inData)
{
    block_num_ = block_offset::serialized_offset_to_block_num(inData);
    free_bytes_ = block_offset::serialized_offset_to_bytes(inData);
    data_ = inData;
}

void pstate::data_node::deserialize_block_num_from_offset(ByteArray& offset)
{
    block_num_ = block_offset::serialized_offset_to_block_num(offset);
}

void pstate::data_node::deserialize_original_encrypted_data_id(StateBlockId& id)
{
    originalEncryptedDataNodeId_ = id;
}

unsigned int pstate::data_node::free_bytes()
{
    return free_bytes_;
}

bool pstate::data_node::enough_space_for_value(bool continue_writing)
{
    if (continue_writing)
    {
        return free_bytes_ >= 1;
    }
    // value in kv is: trie node (but just 1 byte) || size (4 bytes) || string value
    // need at least 6 bytes to proceed (trie node, size and one value byte)
    return free_bytes_ >= sizeof(trie_node_header_t) + sizeof(size_t) + 1;
}

unsigned int pstate::data_node::write(
    const ByteArray& buffer, unsigned int write_from, ByteArray& returnOffSet)
{
    // check that there is enough space to write
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        !enough_space_for_value(write_from > 0), "data node, not enough space to write");

    // compute cursor where to start writing
    unsigned int cursor = data_.size() - free_bytes_;
    // compute return offset
    returnOffSet = make_offset(block_num_, cursor);

    // write the buffer size if necessary
    if (write_from == 0)
    {  // this is the first write
        // write trie node first
        ByteArray ba_trie_node(sizeof(trie_node_header_t), 0);
        trie_node_header_t* h = (trie_node_header_t*)ba_trie_node.data();
        *h = empty_trie_header;
        h->isValue = 1;
        std::copy(ba_trie_node.begin(), ba_trie_node.end(), data_.begin() + cursor);
        cursor += ba_trie_node.size();
        free_bytes_ -= ba_trie_node.size();

        // write buffer size second
        size_t buffer_size = buffer.size();
        ByteArray ba_buffer_size(
            (uint8_t*)&buffer_size, (uint8_t*)&buffer_size + sizeof(buffer_size));
        std::copy(ba_buffer_size.begin(), ba_buffer_size.end(), data_.begin() + cursor);
        cursor += ba_buffer_size.size();
        free_bytes_ -= ba_buffer_size.size();
    }

    // write as much buffer as possible
    unsigned int buffer_size = buffer.size() - write_from;
    unsigned int bytes_to_write = (free_bytes_ > buffer_size ? buffer_size : free_bytes_);
    std::copy(buffer.begin() + write_from, buffer.begin() + write_from + bytes_to_write,
        data_.begin() + cursor);
    free_bytes_ -= bytes_to_write;
    // return bytes that have been written
    return bytes_to_write;
}

unsigned int pstate::data_node::read(const ByteArray& offset,
    ByteArray& outBuffer,
    bool continue_reading,
    unsigned int continue_reading_bytes)
{
    // point cursor at beginning of data
    unsigned int cursor = block_offset::offset_size();
    unsigned int total_bytes_to_read = continue_reading_bytes;
    if (!continue_reading)
    {
        // the provided offset must contain the block num of the current data node
        pdo::error::ThrowIf<pdo::error::ValueError>(
            block_offset::serialized_offset_to_block_num(offset) != block_num_,
            "data node, block num mismatch in offset");
        // update the cursor
        cursor = block_offset::serialized_offset_to_bytes(offset);

        // read trie node header (1 byte) first
        ByteArray ba_trie_node(
            data_.begin() + cursor, data_.begin() + cursor + sizeof(trie_node_header_t));
        cursor += sizeof(trie_node_header_t);
        trie_node_header_t* h = (trie_node_header_t*)ba_trie_node.data();
        pdo::error::ThrowIf<pdo::error::ValueError>(
            !h->isValue, "stored value does not have value trie node header");

        // read the buffer size second
        ByteArray ba_buffer_size(data_.begin() + cursor, data_.begin() + cursor + sizeof(size_t));
        cursor += sizeof(size_t);
        size_t buffer_size = *((size_t*)ba_buffer_size.data());
        // update the byte to read
        total_bytes_to_read = buffer_size;
    }

    // read as much as possible in outbuffer
    unsigned int bytes_to_endof_data = data_.size() - cursor;
    unsigned int bytes_to_read =
        (total_bytes_to_read < bytes_to_endof_data ? total_bytes_to_read : bytes_to_endof_data);
    pdo::error::ThrowIf<pdo::error::ValueError>(
        bytes_to_read + cursor > data_.size(), "data node, bytes_to_read overflows");
    outBuffer.insert(
        outBuffer.end(), data_.begin() + cursor, data_.begin() + cursor + bytes_to_read);
    // update to total bytes that are still left to read
    total_bytes_to_read -= bytes_to_read;
    return total_bytes_to_read;  // if 0, read is complete, otherwise it must continue with the next
                                 // data node
}

uint8_t* pstate::data_node::offset_to_pointer(const ByteArray& offset)
{
    pdo::error::ThrowIf<pdo::error::ValueError>(
        block_offset::serialized_offset_to_block_num(offset) != block_num_,
        "request pointer does not match block num");

    unsigned int cursor = block_offset::serialized_offset_to_bytes(offset);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(cursor > FIXED_DATA_NODE_BYTE_SIZE - free_bytes_,
        "error setting cursor in offset to pointer");

    return data_.data() + cursor;
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

pstate::trie_node_header_t* pstate::data_node::write_trie_node(bool isDeleted,
    bool hasNext,
    bool hasChild,
    const ByteArray& key,
    unsigned int keyChunkBegin,
    unsigned int keyChunkEnd,
    ByteArray& returnOffset)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(!hasNext, "new header must have next");
    pdo::error::ThrowIf<pdo::error::RuntimeError>(!hasChild, "new header must have child");

    size_t space_required = trie_node::new_trie_node_size();

    // check that there is enough space to write
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        free_bytes_ < space_required, "no space to write trie node");
    // compute cursor where to start writing
    unsigned int cursor = data_.size() - free_bytes_;
    pdo::error::ThrowIf<pdo::error::RuntimeError>(cursor > FIXED_DATA_NODE_BYTE_SIZE - free_bytes_,
        "error setting cursor in offset to pointer");

    // compute return offset
    returnOffset = make_offset(block_num_, cursor);
    // write structure
    trie_node_header_t* returnHeader = (trie_node_header_t*)(data_.data() + cursor);
    returnHeader->hasNext = 1;
    returnHeader->hasChild = 1;
    *(trie_node::goto_next_offset(returnHeader)) = empty_block_offset;
    *(trie_node::goto_child_offset(returnHeader)) = empty_block_offset;
    // compute key chunk length that can be copied
    size_t kcl = keyChunkEnd - keyChunkBegin;
    // recall that returnHeader->keyChunkSize has limits
    returnHeader->keyChunkSize = (kcl > MAX_KEY_CHUNK_BYTE_SIZE ? MAX_KEY_CHUNK_BYTE_SIZE : kcl);

    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        returnHeader->keyChunkSize != kcl && returnHeader->keyChunkSize != MAX_KEY_CHUNK_BYTE_SIZE,
        "bad variable assignement in key chunk length");

    // copy only what can be written, aligned at the beginning of key chunk
    std::copy(key.begin() + keyChunkBegin, key.begin() + keyChunkBegin + returnHeader->keyChunkSize,
        trie_node::goto_key_chunk(returnHeader));
    // consume written space
    free_bytes_ -= space_required;
    return returnHeader;
}

void pstate::data_node_io::init_append_data_node()
{
    // the append node to be inited already exists, grab it
    StateBlockId data_node_id;
    block_warehouse_.get_datablock_id_from_datablock_num(
        block_warehouse_.last_appended_data_block_num_, data_node_id);
    append_dn_ = &cache_retrieve(block_warehouse_.last_appended_data_block_num_, true);
    cache_done(block_warehouse_.last_appended_data_block_num_,
        true);  // nobody is using it now; new nodes are modified
}

void pstate::data_node_io::add_and_init_append_data_node()
{
    // make space in cache if necessary
    cache_unpin(block_warehouse_.last_appended_data_block_num_);
    cache_replacement_policy();

    // allocate and initialized data node
    append_dn_ = cache_slots_.allocate();
    pdo::error::ThrowIf<pdo::error::RuntimeError>(!append_dn_, "slot allocate, null pointer");
    *append_dn_ = data_node(++block_warehouse_.last_appended_data_block_num_);

    // put and pin it in cache
    cache_put(block_warehouse_.last_appended_data_block_num_, append_dn_);
    cache_pin(block_warehouse_.last_appended_data_block_num_);
    cache_modified(block_warehouse_.last_appended_data_block_num_);

    // add empty id in list
    StateBlockId dn_id(STATE_BLOCK_ID_LENGTH, 0);
    block_warehouse_.add_datablock_id(dn_id);
}

void pstate::data_node_io::add_and_init_append_data_node_cond(bool cond)
{
    if (cond)
        pstate::data_node_io::add_and_init_append_data_node();
}

void pstate::data_node_io::cache_replacement_policy()
{
    while (block_cache_.size() >= BLOCK_CACHE_MAX_ITEMS)
    {
        int index_to_remove = -1;
        uint64_t clock = UINT64_MAX;
        std::map<unsigned int, block_cache_entry_t>::iterator it;

        for (it = block_cache_.begin(); it != block_cache_.end(); ++it)
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
        cache_flush_entry(index_to_remove);
    }
}

void pstate::data_node_io::cache_drop_entry(unsigned int block_num)
{
    std::map<unsigned int, block_cache_entry_t>::iterator it;
    it = block_cache_.find(block_num);
    block_cache_entry_t& bce = it->second;
    cache_slots_.release(&(bce.dn));
    block_cache_.erase(it);
}

void pstate::data_node_io::cache_drop()
{
    std::map<unsigned int, block_cache_entry_t>::iterator it;
    while (!block_cache_.empty())
    {
        it = block_cache_.begin();
        cache_drop_entry(it->first);
    }
}

void pstate::data_node_io::cache_flush_entry(unsigned int block_num)
{
    // sync
    cache_sync_entry(block_num);
    // drop
    cache_drop_entry(block_num);
}

void pstate::data_node_io::cache_flush()
{
    std::map<unsigned int, block_cache_entry_t>::iterator it;
    while (!block_cache_.empty())
    {
        it = block_cache_.begin();
        cache_flush_entry(it->first);
    }
}

void pstate::data_node_io::cache_sync_entry(unsigned int block_num)
{
    std::map<unsigned int, block_cache_entry_t>::iterator it;

    it = block_cache_.find(block_num);
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

void pstate::data_node_io::cache_sync()
{
    std::map<unsigned int, block_cache_entry_t>::iterator it;
    for (it = block_cache_.begin(); it != block_cache_.end(); ++it)
    {
        cache_sync_entry(it->first);
    }
}

void pstate::data_node_io::cache_put(unsigned int block_num, data_node* dn)
{
    block_cache_entry_t bce;
    bce.dn = dn;
    bce.references = 0;
    bce.modified = false;
    bce.pinned = false;
    bce.clock = (cache_clock_++);
    block_cache_[block_num] = bce;
}

pstate::data_node& pstate::data_node_io::cache_retrieve(unsigned int block_num, bool pinned)
{
    if (block_cache_.count(block_num) == 0)
    {  // not in cache
        pstate::data_node_io::cache_replacement_policy();

        StateBlockId data_node_id;
        block_warehouse_.get_datablock_id_from_datablock_num(block_num, data_node_id);

        // allocate data node and load block into it
        data_node* dn = cache_slots_.allocate();
        pdo::error::ThrowIf<pdo::error::RuntimeError>(!dn, "slot allocate, null pointer");
        dn->deserialize_original_encrypted_data_id(data_node_id);
        dn->load(block_warehouse_.state_encryption_key_);

        // cache it
        cache_put(block_num, dn);

        if (pinned)
            cache_pin(block_num);
    }
    // now it is in cache, grab it
    block_cache_entry_t& bce = block_cache_[block_num];
    bce.references++;
    return *bce.dn;
}

void pstate::data_node_io::cache_done(unsigned int block_num, bool modified)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        block_cache_.count(block_num) == 0, "cache done, item not in cache");
    block_cache_entry_t& bce = block_cache_[block_num];
    bce.references--;
    if (modified)
        bce.modified = modified;
}

void pstate::data_node_io::cache_pin(unsigned int block_num)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        block_cache_.count(block_num) == 0, "cache done, item not in cache");
    block_cache_entry_t& bce = block_cache_[block_num];
    bce.pinned = true;
}

void pstate::data_node_io::cache_unpin(unsigned int block_num)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        block_cache_.count(block_num) == 0, "cache done, item not in cache");
    block_cache_entry_t& bce = block_cache_[block_num];
    bce.pinned = false;
}

void pstate::data_node_io::cache_modified(unsigned int block_num)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        block_cache_.count(block_num) == 0, "cache done, item not in cache");
    block_cache_entry_t& bce = block_cache_[block_num];
    bce.modified = true;
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
    StateBlockIdRefArray refArray = node.GetChildrenBlocks();
    blockIds_ = StateBlockIdRefArray_To_StateBlockIdArray(refArray);
}

void pdo::state::block_warehouse::update_block_id(
    pstate::StateBlockId& prevId, pstate::StateBlockId& newId)
{
    std::replace(blockIds_.begin(), blockIds_.end(), prevId, newId);
}

void pdo::state::block_warehouse::update_datablock_id(
    unsigned int data_block_num, pdo::state::StateBlockId& newId)
{
    unsigned int index = blockIds_.size() - 1 - last_appended_data_block_num_ + data_block_num;
    blockIds_[index] = newId;
}

void pdo::state::block_warehouse::add_block_id(pstate::StateBlockId& id)
{
    blockIds_.push_back(id);
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

void pdo::state::block_warehouse::add_datablock_id(pstate::StateBlockId& id)
{
    blockIds_.push_back(id);
}

void pdo::state::block_warehouse::get_datablock_id_from_datablock_num(
    unsigned int data_block_num, pdo::state::StateBlockId& outId)
{
    // CONVENTION:   the data blocks are put in sequential order in the list,
    //              where the last block is the last appended data block, namely:
    //              last item of blockIds_ is the data block with block num
    //              last_appended_data_block_num_
    unsigned int index = blockIds_.size() - 1 - last_appended_data_block_num_ + data_block_num;
    outId = blockIds_[index];
}

unsigned int pdo::state::block_warehouse::get_root_block_num()
{
    return 0;  // convention
}

void pdo::state::block_warehouse::get_last_datablock_id(pdo::state::StateBlockId& outId)
{
    outId = blockIds_[blockIds_.size() - 1];
}

pdo::state::State_KV::State_KV(ByteArray& id)
    : Basic_KV(id), dn_io_(data_node_io(empty_state_encryption_key_))
{
}

pdo::state::State_KV::State_KV(const ByteArray& key)
    : Basic_KV(), state_encryption_key_(key), dn_io_(data_node_io(key))
{
    // initialize first data node
    dn_io_.block_warehouse_.last_appended_data_block_num_ =
        dn_io_.block_warehouse_.get_root_block_num();
    data_node dn(dn_io_.block_warehouse_.last_appended_data_block_num_);
    StateBlockId dn_id;
    dn.unload(state_encryption_key_, dn_id);
    dn_io_.block_warehouse_.add_datablock_id(dn_id);

    // cache and pin first data node
    dn_io_.init_append_data_node();

    // init trie root node in first data node
    trie_node::init_trie_root(dn_io_);

    // add new data node
    dn_io_.add_and_init_append_data_node();
    // pin in cache the first one
    dn_io_.cache_pin(dn_io_.block_warehouse_.get_root_block_num());
}

pdo::state::State_KV::State_KV(const StateBlockId& id, const ByteArray& key)
    : Basic_KV(id), state_encryption_key_(key), dn_io_(data_node_io(key))
{
    // retrieve main state block, root node and last data node
    rootNode_.GetBlockId() = id;
    state_status_t ret;
    ret = sebio_fetch(id, SEBIO_NO_CRYPTO, rootNode_.GetBlock());
    pdo::error::ThrowIf<pdo::error::ValueError>(
        ret != STATE_SUCCESS, "statekv::init, sebio returned an error");

    // deserialize blocks ids in root block
    dn_io_.block_warehouse_.deserialize_block_ids(rootNode_);

    // retrieve last data block num from last appended data block
    dn_io_.block_warehouse_.last_appended_data_block_num_ =
        dn_io_.block_warehouse_.blockIds_.size() - 1;
    dn_io_.init_append_data_node();
}

void pdo::state::State_KV::Finalize(ByteArray& outId)
{
    // flush cache first
    dn_io_.cache_flush();

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

ByteArray pstate::State_KV::Get(const ByteArray& key)
{
    // perform operation
    ByteArray value;
    const ByteArray& kvkey = key;
    trie_node::operate_trie_root(dn_io_, GET_OP, kvkey, value);
    return value;
}

void pstate::State_KV::__on_error__(const char* what)
{
    // remove any block that was appended for writing and has a (currently) empty id
    dn_io_.block_warehouse_.remove_empty_block_ids();
    // maybe something was accessed, written, appended. just drop all!
    dn_io_.cache_drop();
    // after delete and drop, we need to re-init the last append data node (ready for the next
    // operation)
    dn_io_.block_warehouse_.last_appended_data_block_num_ =
        dn_io_.block_warehouse_.blockIds_.size() - 1;
    dn_io_.init_append_data_node();
    SAFE_LOG(PDO_LOG_ERROR, "%s", what);
    throw pdo::error::Error(
        PDO_ERR_RUNTIME, std::string("put failed, ") + std::string(what));
}

void pstate::State_KV::Put(const ByteArray& key, const ByteArray& value)
{
    // perform operation
    const ByteArray& kvkey = key;
    ByteArray v = value;
    try
    {
        trie_node::operate_trie_root(dn_io_, PUT_OP, kvkey, v);
    }
    catch (pdo::error::RuntimeError& e)
    {
        __on_error__(e.what());
    }
    catch (pdo::error::ValueError& e)
    {
        __on_error__(e.what());
    }
    catch (std::exception& e)
    {
        __on_error__(e.what());
    }
    catch(...)
    {
        __on_error__("unknown exception in KV store");
    }
}

void pstate::State_KV::Delete(const ByteArray& key)
{
    // perform operation
    ByteArray value;
    const ByteArray& kvkey = key;
    trie_node::operate_trie_root(dn_io_, DEL_OP, kvkey, value);
}
