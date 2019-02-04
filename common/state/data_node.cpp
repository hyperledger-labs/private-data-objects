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
