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
    class free_space_collector
    {
        typedef struct {
            block_offset_t bo;
            unsigned int length;
        } free_space_item_t;

    private:
        bool is_collection_modified = false;
        bool is_fsi_deferred = false;
        free_space_item_t deferred_fsi;

        std::vector<free_space_item_t> free_space_collection;

        bool are_adjacent(const block_offset_t& bo1, const unsigned& length1, const block_offset_t& bo2);
        void insert_free_space_item(std::vector<free_space_item_t>::iterator& it, free_space_item_t& fsi);
        void do_collect(free_space_item_t& fsi);

    public:
        StateBlockId original_block_id_of_collection;

        void collect(const block_offset_t& bo, const unsigned int& length);
        bool allocate(const unsigned int& length, block_offset_t& out_bo);
        bool collection_modified();
        void serialize_in_data_node(data_node &out_dn);
        void deserialize_from_data_node(data_node &in_dn);
    };
}
}
