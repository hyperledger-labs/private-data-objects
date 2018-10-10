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

#include "types.h"
#include "error.h"
#include "state.h"

namespace pstate = pdo::state;

#ifdef DEBUG
    #define SAFE_LOG(LEVEL, FMT, ...) Log(LEVEL, FMT, ##__VA_ARGS__)
#else // DEBUG not defined
    #define SAFE_LOG(LEVEL, FMT, ...)
#endif // DEBUG

/* 
    Global variable for the State Abstraction Layer.
    This is used by any code developed above the abstraction to access
    (i.e., open, close, read, write) named content (i.e., an id is required).
*/
pdo::state::sal g_sal;

//##################### INTERNAL CLASS
/*
    The sal_handle is an internal data structure used to maintain information about
    the currently accessed state, e.g., the cursor and (currently) the data block itself
*/
class sal_handle {
public:
    uint64_t cursor;
    ByteArray* block;
    pstate::StateNode* node;
    sal_handle(pstate::StateNode& stateNode) {
        cursor = 0;
        node = &stateNode;
        block = &(node->GetBlock());
    }
};

//###################### STATE ABSTRACTION LAYER
/*
    The SAL is initialized using the state root (for extrinsic state) in the contract state.
    Then, other code that uses the SAL (e.g., a key value store) is assumed to have the id
    (i.e., sha256 hash) of the data it wants to open and read/write.
*/
pdo::state::sal::sal() {
    initialized_ = false;
    rootNode = NULL;
}

/*
    It initializes the SAL starting from the root id.
    If the id is empty it creates a new block to put ids.
    If the id is not empty it attempts to retrieve the correspondig data block,
    and makes it available for sal_open.
    The caller can check what ids can be opened through sal_list.
*/
void pdo::state::sal::init(ByteArray& rootId) {
    pdo::error::ThrowIf<pdo::error::ValueError>(
        initialized_, "sal::init, already initialized");

    if(rootId.empty()) { //no id, create state root
        SAFE_LOG(PDO_LOG_DEBUG, "SAL init: creating new state");
        rootNode = new pdo::state::StateNode(*new StateBlockId(), *new StateBlock());
        //initialize block with 0 children (as if we just retrieved it)
        rootNode->BlockifyChildren();
    }
    else { //retrieve main state block
        uint8_t* block;
        size_t block_size;
        state_status_t ret;
        SAFE_LOG(PDO_LOG_DEBUG, "SAL init: root id: %s", ByteArrayToHexEncodedString(rootId).c_str());
        ret = sebio_fetch(rootId.data(), rootId.size(), SEBIO_NO_CRYPTO, &block, &block_size);
        pdo::error::ThrowIf<pdo::error::ValueError>(
            ret != STATE_SUCCESS, "sal::init, sebio returned an error");
        rootNode = new pdo::state::StateNode(*new StateBlockId(rootId), *new StateBlock(block, block + block_size));
        free(block); //allocated by sebio
    }

    rootNode->UnBlockifyChildren();
    initialized_ = true;
}

/*
    The SAL list function returns the id's of the children (of the main block) that can be later opened
*/
pstate::StateBlockIdRefArray pdo::state::sal::list() {
    pdo::error::ThrowIf<pdo::error::ValueError>(
            !initialized_, "sal::list, sal not initialized");
    return rootNode->GetChildrenBlocks();
}

/*
    The SAL uninitialization returns a copy of the identity (i.e., root hash).
    This is the root of the extrinsic state.
*/
state_status_t pdo::state::sal::uninit(StateBlockId* rootId) {
    if(!initialized_) {
        return STATE_ERR_RUNTIME;
    }
    rootNode->BlockifyChildren();
    rootNode->ReIdentify();
    StateBlock b = rootNode->GetBlock();
    state_status_t ret = sebio_evict(b.data(), b.size(), SEBIO_NO_CRYPTO, rootNode->GetBlockId());
    pdo::error::ThrowIf<pdo::error::ValueError>(
            ret != STATE_SUCCESS, "sal::uninit, sebio returned an error");
    *rootId = rootNode->GetBlockId();
    delete rootNode;
    initialized_ = false;
    SAFE_LOG(PDO_LOG_DEBUG, "SAL uninit: root id: %s", ByteArrayToHexEncodedString(*rootId).c_str());
    return STATE_SUCCESS;
}

/*
    The SAL Initialized function simply returns whether the SAL is initialized or not
*/
bool pdo::state::sal::initialized() {
    return initialized_;
}

/*
    The open function takes as input an id.
    If the id is empty, a new child is created (e.g., the root hash of a KV store that has just been created).
    If the id is not empty, then this should match a child of the current node in the hierarchy.
    In case of success, a handle is returned, and can be used for reading and writing data.
*/
state_status_t pdo::state::sal::open(ByteArray& id, void **handle) {
    *handle = NULL;
    StateNodeRef nodeRef;

    if(id.empty()) { //empty id -> create it
        SAFE_LOG(PDO_LOG_DEBUG, "SAL open, creating empty block");
        nodeRef = new StateNode(*new StateBlockId(), *new StateBlock());
        rootNode->AppendChild(*nodeRef);
    }
    else { //non-empty id -> find it
        SAFE_LOG(PDO_LOG_DEBUG, "SAL open, id: %s", ByteArrayToHexEncodedString(id).c_str());
        StateBlockIdRef childIdRef = rootNode->LookupChild(id);
        if(!childIdRef) { //error, no child found
            return STATE_ERR_NOT_FOUND;
        }
        //it's a child, so retrieve block
        uint8_t* block;
        size_t block_size;
        state_status_t ret;
        ret = sebio_fetch(id.data(), id.size(), SEBIO_AES_GCM, &block, &block_size);
        if(ret != STATE_SUCCESS) {
            SAFE_LOG(PDO_LOG_DEBUG, "error, sebio ret %d", ret);
            std::string msg("sal::open, sebio returned an error");
            throw pdo::error::ValueError(msg);
        }
        nodeRef = new StateNode(*childIdRef, *new StateBlock(block, block + block_size));
        nodeRef->SetHasParent();
        free(block);//free buffer from sebio (convention)
    }
    
    *handle = new sal_handle(*nodeRef);
    return STATE_SUCCESS;
}

/*
    The read operation appends up to 'bytes' of data into the output buffer, starting from the current cursor.
    If the read operation overflows, it still appends as many bytes as possible and returns an EOD
    (End Of Data) value.
*/
state_status_t pdo::state::sal::read(void* handle, size_t bytes, ByteArray &output_buffer) {
    sal_handle* h = (sal_handle*)handle;
    state_status_t ret;
    uint64_t new_cursor = h->cursor + bytes;
    StateBlock::const_iterator first = h->block->begin() + h->cursor;
    //find the point where we end reading (i.e., at most the end of the block)
    StateBlock::const_iterator last;
    StateBlock::const_iterator expected_last = h->block->begin() + new_cursor;
    if(expected_last > h->block->end()) {
        last = h->block->end();
        h->cursor = h->block->size();
        ret = STATE_EOD;
    }
    else {
        last = expected_last;
        h->cursor = new_cursor;
        ret = STATE_SUCCESS;
    }
    output_buffer.insert(output_buffer.end(), first, last);
    return ret;
}

/*
    The write operation takes an input buffer an writes the data in the opened state,
    starting from the current cursor.
*/
state_status_t pdo::state::sal::write(void* handle, ByteArray &input_buffer) {
    sal_handle* h = (sal_handle*)handle;
    {//perform erase (if necessary) to emulate overwriting of existing data
        uint64_t cursor_to_end_bytes = h->block->size() - h->cursor;
        int64_t bytes_to_insert = (input_buffer.size() - cursor_to_end_bytes < 0 ?
                                    0 : input_buffer.size() - cursor_to_end_bytes);
        uint64_t bytes_to_overwrite = input_buffer.size() - bytes_to_insert;
        pdo::error::ThrowIf<pdo::error::ValueError>(
                bytes_to_insert + bytes_to_overwrite != input_buffer.size(),
                "sal write, bytes to insert/overwrite error");
        h->block->erase(h->block->begin() + h->cursor, h->block->begin() + h->cursor + bytes_to_overwrite);
    }
    //perform write
    try 
    {
        h->block->insert(h->block->begin() + h->cursor, input_buffer.begin(), input_buffer.end());
    }
    catch(const std::bad_alloc &)
    {
         SAFE_LOG(PDO_LOG_DEBUG, "sal::write, out of memory");
         std::string msg("sal::write, insert error, out of memory");
         throw pdo::error::MemoryError(msg);
    }
    catch (...)
    {
         std::string msg("sal::write, insert error");
         throw pdo::error::RuntimeError(msg);
    }
    h->cursor += input_buffer.size();
    return STATE_SUCCESS;
}

/*
    The seek operation moves the cursor backward or forward of a specified offset.
    The highest negative (resp. positive) offset is interpreted as the first (resp. last) byte of the state.
*/
state_status_t pdo::state::sal::seek(void* handle, int64_t offset) {
    sal_handle* h = (sal_handle*)handle;

    switch(offset) {
        case INT64_MIN:
            h->cursor = 0; // beginning
            break;
        case INT64_MAX:
            h->cursor = h->block->size();
            break;
        default:
            if(h->cursor + offset <= h->block->size()) {
                h->cursor += offset;
                break;
            }
            else {
                return STATE_ERR_OVERFLOW;
            }
    }
    return STATE_SUCCESS;
}

/*
    The truncate_here operation drops all data after the cursor, reduces the size of the data block,
    and leaves the cursor at the end of the block.
*/
state_status_t pdo::state::sal::truncate_here(void* handle) {
    sal_handle* h = (sal_handle*)handle;
    SAFE_LOG(PDO_LOG_DEBUG, "SAL truncate: block size %u, cursor %llu", h->block->size(), h->cursor);
    StateBlock::const_iterator first = h->block->begin() + h->cursor;
    StateBlock::const_iterator last = h->block->end();
    h->block->erase(first, last);
    SAFE_LOG(PDO_LOG_DEBUG, "SAL truncate: block size %u, cursor %llu", h->block->size(), h->cursor);
    return STATE_SUCCESS;
}

/*
    The close operation frees resources, evicts the blocks that are now unnecessary and returns
*/
state_status_t pdo::state::sal::close(void **handle, pstate::StateBlockId* id) {
    sal_handle* h = *(sal_handle**)handle;
    state_status_t ret;

    //evict unnecessary block
    pstate::StateBlock& b = h->node->GetBlock();
    ret = sebio_evict(b.data(), b.size(), SEBIO_AES_GCM, h->node->GetBlockId());
    *id = h->node->GetBlockId();
    SAFE_LOG(PDO_LOG_DEBUG, "SAL closed: evicted id: %s", ByteArrayToHexEncodedString(*id).c_str());
    pdo::error::ThrowIf<pdo::error::ValueError>(
            ret != STATE_SUCCESS, "sal::close, sebio returned an error");
    //free resources
    delete h->node;
    delete h;
    *handle = NULL;
    return STATE_SUCCESS;
}
