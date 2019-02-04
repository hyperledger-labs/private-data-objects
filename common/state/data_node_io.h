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
    class data_node_io
    {
    public:
        block_warehouse block_warehouse_;
        free_space_collector free_space_collector_;
        // append_dn points to a data note pinned in cache
        data_node* append_dn_;
        Cache cache_;

        data_node_io(const ByteArray& key) : block_warehouse_(key), cache_(block_warehouse_) {}
        void initialize(pdo::state::StateNode& node);

        void init_append_data_node();
        void add_and_init_append_data_node();
        void add_and_init_append_data_node_cond(bool cond);
        void consume_add_and_init_append_data_node();
        void consume_add_and_init_append_data_node_cond(bool cond);
        void block_offset_for_appending(block_offset_t& out_bo);

        void write_across_data_nodes(const ByteArray& buffer, unsigned int write_from, const block_offset_t& bo_at);
        void read_across_data_nodes(const block_offset_t& bo_at, unsigned int length, ByteArray& outBuffer);
    };
}
}
