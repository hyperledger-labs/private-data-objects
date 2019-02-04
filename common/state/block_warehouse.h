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
    class block_warehouse
    {
    private:
        pdo::state::StateBlockIdArray blockIds_ = {};

    public:
        const ByteArray state_encryption_key_;

        block_warehouse(const ByteArray& state_encryption_key)
            : state_encryption_key_(state_encryption_key)
        {
        }

        void serialize_block_ids(pdo::state::StateNode& node);
        void deserialize_block_ids(pdo::state::StateNode& node);

        void update_datablock_id(unsigned int data_block_num, pdo::state::StateBlockId& newId);

        void add_block_id(pdo::state::StateBlockId& id);

        void remove_empty_block_ids();
        void remove_block_id_from_datablock_num(unsigned int data_block_num);

        void get_datablock_id_from_datablock_num(
            unsigned int data_block_num, pdo::state::StateBlockId& outId);
        unsigned int get_root_block_num();
        unsigned int get_last_block_num();
    };
}
}
