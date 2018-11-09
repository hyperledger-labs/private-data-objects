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

#pragma once

#include "types.h"
#include "basic_kv.h"

#define STATE_KV_DEFAULT_FIXED_KEY_SIZE 16 //bytes

namespace pdo
{
    namespace state
    {
        class StateKV_Key
        {
        protected:
            ByteArray fixed_size_key_;
        public:
            StateKV_Key(ByteArray& key);
            StateKV_Key(ByteArray& key, size_t wanted_key_size);
            const ByteArray& Get_Key();
        };

        class kv_node;
        class data_node;

        class State_KV : public Basic_KV
        {
        protected:
            pdo::state::StateNode* rootNode_;
            pdo::state::StateBlockIdArray blockIds_ = {};
            ByteArray state_encryption_key_;
            unsigned int last_appended_data_block_num_;
            size_t fixed_key_size_ = 0;

            void serialize_block_ids();
            void deserialize_block_ids();
            void update_block_id(pdo::state::StateBlockId& prevId, pdo::state::StateBlockId& newId);
            void add_block_id(pdo::state::StateBlockId& id);
            void add_kvblock_id(pdo::state::StateBlockId& id);
            void add_datablock_id(pdo::state::StateBlockId& id);
            void get_datablock_id_from_datablock_num(unsigned int data_block_num, pdo::state::StateBlockId& outId);
            void get_search_root_kvblock_id(pdo::state::StateBlockId& outId);
            void get_last_datablock_id(pdo::state::StateBlockId& outId);

            void error_on_wrong_key_size(size_t key_size);
            void operate(kv_node& search_kv_node, unsigned int operation, const ByteArray& kvkey, ByteArray& value);

        public:
            State_KV(ByteArray& id);
            State_KV(ByteArray& id, const ByteArray& key);
            State_KV(ByteArray& id, const ByteArray& key, const size_t fixed_key_size);
            ~State_KV();

            void Uninit(ByteArray& id);

            ByteArray Get(ByteArray& key);
            void Put(ByteArray& key, ByteArray& value);
            void Delete(ByteArray& key);

            ByteArray Get(pdo::state::StateKV_Key& statekv_key);
            void Put(pdo::state::StateKV_Key& key, ByteArray& value);
            void Delete(pdo::state::StateKV_Key& key);
        };
    }
}
