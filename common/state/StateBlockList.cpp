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

#include "StateBlockList.h"
#include <map>
#include "packages/base64/base64.h"
#include "c11_support.h"
#include "state.h"
#include "error.h"

#ifdef DEBUG
    #define SAFE_LOG(LEVEL, FMT, ...) Log(LEVEL, FMT, ##__VA_ARGS__)
#else // DEBUG not defined
    #define SAFE_LOG(LEVEL, FMT, ...)
#endif // DEBUG

namespace pstate = pdo::state;

std::map<pstate::StateBlockId, pstate::StateBlock> cache_;

//######################## INTERNAL FUNCTIONS ##############
/*
    These are Eusebio hook calls. Any code can use these to make sebio grab
    blocks from a local cache, rather that from the block store.
    The work by intercepting the block I/O of the SAL at a low level,
    so that blocks are retrieved and not decrypted (because no key is available)
    by the client.
*/

state_status_t sebio_fetch_hook(
    uint8_t* block_id,
    size_t block_id_size,
    sebio_crypto_algo_e crypto_algo,
    uint8_t** block,
    size_t* block_size) 
{
    ByteArray baBlockId(block_id, block_id + block_id_size);
    if (cache_.find(baBlockId) == cache_.end()) {
        // report error
        return STATE_ERR_NOT_FOUND;
    }
    //else
    ByteArray baBlock = cache_[baBlockId];
    *block_size = baBlock.size();
    *block = (uint8_t*) malloc(*block_size);
    if(*block == NULL) {
        return STATE_ERR_MEMORY;
    }
    memcpy_s(*block, *block_size, baBlock.data(), baBlock.size());
    return STATE_SUCCESS;   
}

state_status_t sebio_evict_hook(
    uint8_t* block,
    size_t block_size,
    sebio_crypto_algo_e crypto_algo,
    ByteArray& idOnEviction) 
{
    //not necessary (for now)
    return STATE_SUCCESS;
}

//##########################################################

void pstate::WarmUpCache(const Base64EncodedString& b64BlockId, const Base64EncodedString& b64BlockData) 
{
    ByteArray blockId = base64_decode(b64BlockId);
    ByteArray blockData = base64_decode(b64BlockData);
    cache_[blockId] = blockData; 
}

void pstate::ClearCache()
{
    cache_.clear();
}

/*
    Global variable to store the needed block when the block list cannot be completed
*/
pstate::StateBlockId neededBlockId;

/* 
    GetStateBlockList return a list of the block id's in the state,
    "OR"
    it sets the neededBlockId variable and raises an exception
    (in this case the caller can use the GetMissingBlockId variable to get the value).
    The return value is a byte array of concatenated IDs.
    It is assumed that the caller knows the size of an ID.
*/
ByteArray pstate::GetStateBlockList(const pstate::StateBlockId& stateId)
{
    // set Eusebio to use the local cache, 
    // which has been initially warmed up (e.g., by the client)
    sebio_set({{}, SEBIO_NO_CRYPTO, &sebio_fetch_hook, &sebio_evict_hook});
    
    try {
        pstate::StateBlockId id = stateId;
        g_sal.init(id);
    }
    catch(const pdo::error::ValueError& e) {
        //sebio must have returned an error, so block not found in cache
        neededBlockId = stateId;
        std::string msg("GetStateBlockList, missing block with id " + ByteArrayToHexEncodedString(stateId));
        throw pdo::error::ValueError(msg);
    }
    
    pstate::StateBlockIdRefArray refArray = g_sal.list();
    for(unsigned int i=0; i<refArray.size(); i++) {
        StateBlockIdRef& ref = refArray[i];
        try {
            void *h;
            g_sal.open(*ref, &h);
            g_sal.close(&h, ref);
        }
        catch(const pdo::error::ValueError& e) {
            //sebio must have returned an error, so block not found in cache
            neededBlockId = *ref;
            pdo::state::StateBlockId id;
            g_sal.uninit(&id);
            std::string msg("GetStateBlockList, missing block with id " + ByteArrayToHexEncodedString(*ref));
            throw pdo::error::ValueError(msg);
        }
    }
    //append root
    ByteArray concatenatedIds;
    concatenatedIds.insert(concatenatedIds.end(), stateId.begin(), stateId.end());
    ByteArray b = pstate::StateBlockIdRefArray_To_ByteArray(refArray);
    concatenatedIds.insert(concatenatedIds.end(), b.begin(), b.end());
    pdo::state::StateBlockId id;
    g_sal.uninit(&id);
    return concatenatedIds;
}

/*
    Returns the value of the neededBlockId global variable.
    This function is meant to be used by a caller when GetStateBlockList 
    cannot find a block and raises an exception.
*/
pstate::StateBlockId pstate::GetMissingBlockId() {
    return neededBlockId;
}
