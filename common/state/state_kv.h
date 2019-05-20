/* Copyright 2018, 2019 Intel Corporation
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
    const ByteArray empty_state_encryption_key_ = ByteArray(16, 0);

    class State_KV : public Basic_KV
    {
        typedef enum
        {
            KV_UNINITIALIZED,
            KV_CREATE,
            KV_OPEN
        } kv_start_mode_e;

    protected:
        pdo::state::StateNode rootNode_;
        const ByteArray state_encryption_key_;
        mutable data_node_io dn_io_;
        kv_start_mode_e kv_start_mode = KV_UNINITIALIZED;

    public:
        State_KV(const ByteArray& key);
        State_KV(const StateBlockId& id, const ByteArray& key);

        void Finalize(ByteArray& id);

        ByteArray Get(const ByteArray& key) const;
        void Put(const ByteArray& key, const ByteArray& value);
        void Delete(const ByteArray& key);
    };
}
}
