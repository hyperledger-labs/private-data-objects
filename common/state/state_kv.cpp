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

#include "state.h"

namespace pstate = pdo::state;

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
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        kv_start_mode == KV_UNINITIALIZED, "attempt to finalize uninitialized state");

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

        // if the cache synced modified entries, recompute root block id
        if(dn_io_.cache_.synced_entries() > 0)
        {
            // serialize block ids
            dn_io_.block_warehouse_.serialize_block_ids(rootNode_);

            // evict root block
            ByteArray baBlock = rootNode_.GetBlock();
            state_status_t ret = sebio_evict(baBlock, SEBIO_NO_CRYPTO, rootNode_.GetBlockId());
            pdo::error::ThrowIf<pdo::error::ValueError>(
                ret != STATE_SUCCESS, "kv root node unload, sebio returned an error");
        }

        // output the root id
        outId = rootNode_.GetBlockId();
    }
    catch(const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("finalize kv error");
        throw;
    }
}

ByteArray pstate::State_KV::Get(const ByteArray& key) const
{
    // perform operation
    const ByteArray& kvkey = key;
    const ByteArray in_value;
    ByteArray out_value;
    try
    {
        trie_node::operate_trie_non_recursive(dn_io_, GET_OP, kvkey, in_value, out_value);
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
        trie_node::operate_trie_non_recursive(dn_io_, PUT_OP, kvkey, value, v);
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
        trie_node::operate_trie_non_recursive(dn_io_, DEL_OP, kvkey, in_value, value);
    }
    catch(const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("kv delete error");
        throw;
    }
}
