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
