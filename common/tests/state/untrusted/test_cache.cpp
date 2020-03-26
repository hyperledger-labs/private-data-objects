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

#include "test_state_kv.h"
#include "_kv_gen.h"

namespace pstate = pdo::state;

extern pdo::state::Basic_KV* kv_;

//#### HOOKS for the SEBIO layer which transfers blocks between KVS and LMDB
extern state_status_t sebio_fetch_from_block_store(const pstate::StateBlockId& block_id,
    sebio_crypto_algo_e crypto_algo,
    pstate::StateBlock& block);
extern state_status_t sebio_evict_to_block_store(
    const pstate::StateBlock& block, sebio_crypto_algo_e crypto_algo, ByteArray& idOnEviction);

// We intercept the fetch call to count the number of block fetches
unsigned int fetch_calls = 0;
state_status_t custom_fetch(const pstate::StateBlockId& block_id,
    sebio_crypto_algo_e crypto_algo,
    pstate::StateBlock& block)
{
    fetch_calls ++;
    return sebio_fetch_from_block_store(block_id, crypto_algo, block);
}

// We intercept the evict call to count the number of block evictions
unsigned int evict_calls = 0;
state_status_t custom_evict(
    const pdo::state::StateBlock& block, sebio_crypto_algo_e crypto_algo, ByteArray& idOnEviction)
{
    evict_calls ++;
    return sebio_evict_to_block_store(block, crypto_algo, idOnEviction);
}

void init_test_cache()
{
    sebio_set({{}, SEBIO_NO_CRYPTO, &custom_fetch, &custom_evict});
}

void test_cache()
{
    const ByteArray state_encryption_key_(16, 0);
    ByteArray id;
//################## TEST CACHE EXISTENCE #############################################################################
    try
    {
        SAFE_LOG(PDO_LOG_INFO, "start test cache existence\n");
        pstate::State_KV skv(state_encryption_key_);
        kv_ = &skv;
        std::string key("a");
        std::string value("a");
        _kv_put(key, value);
        unsigned int old_fetch_calls = fetch_calls;
        //read/write of a (small) key/value pair must not result in additional block fetches
        _kv_get(key, value);
        if(old_fetch_calls != fetch_calls)
        {
            SAFE_LOG(PDO_LOG_ERROR, "kv get resulted in block fetch\n");
            throw;
        }
        _kv_put(key, value);
        if(old_fetch_calls != fetch_calls)
        {
            SAFE_LOG(PDO_LOG_ERROR, "kv put resulted in block fetch\n");
            throw;
        }
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KVS cache existence\n");
        throw;
    }
    sebio_set({{}, SEBIO_NO_CRYPTO, &sebio_fetch_from_block_store, &sebio_evict_to_block_store});

//################## TEST CACHE EXAUSTION #############################################################################
    try
    {
        SAFE_LOG(PDO_LOG_INFO, "start test cache exaustion\n");
        pstate::State_KV skv(state_encryption_key_);
        kv_ = &skv;
        //this forces each key in a separate block, since the value size already takes 1 block
        size_t value_size = FIXED_DATA_NODE_BYTE_SIZE;
        std::string value(value_size, 'a');
        std::string base_string("");
        unsigned int max_key_length = 15 + ((CACHE_SIZE / FIXED_DATA_NODE_BYTE_SIZE) / 20);
        while(base_string.length() < max_key_length)
        {
            SAFE_LOG(PDO_LOG_INFO, "Testing key length %u out of %u\n", base_string.length() + 1, max_key_length);
            for(char c = 'a'; c <= 'z'; c++)
            {
                std::string key = base_string + c;
                _kv_put(key, value);
            }
            base_string += 'z';
        }
        _kv_get(base_string, value);
        kv_->Finalize(id);
    }
    catch (...)
    {
        SAFE_LOG(PDO_LOG_ERROR, "error testing KVS cache exaustion\n");
        throw;
    }

    SAFE_LOG(PDO_LOG_INFO, "cache tests successful\n");
}
