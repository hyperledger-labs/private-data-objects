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
}
}
