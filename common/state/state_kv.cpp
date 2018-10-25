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

#include "state.h"
#include "state_kv.h"
#include "basic_kv.h"
#include "jsonvalue.h"
#include "packages/base64/base64.h"
#include "parson.h"
#include "pdo_error.h"
#include "error.h"
#include "types.h"
#include "c11_support.h"
#include "crypto.h"
#include <algorithm>

#ifdef DEBUG
    #define SAFE_LOG(LEVEL, FMT, ...) Log(LEVEL, FMT, ##__VA_ARGS__)
#else // DEBUG not defined
    #define SAFE_LOG(LEVEL, FMT, ...)
#endif // DEBUG

#define FIXED_DATA_NODE_BYTE_SIZE (1<<13) // 8 KB

namespace pstate = pdo::state;

//############ INTERNAL TOOLS ################################################

class pstate::data_node {
    private:
        ByteArray data_;
        pstate::StateBlockId originalEncryptedDataNodeId_;
        unsigned block_num_;
        unsigned int free_bytes_;


        unsigned int offset_to_block_num(ByteArray& offset) {
            return *((unsigned int*)offset.data()); //the first uint
        }

        unsigned int offset_to_bytes_off(ByteArray& offset) {
            return *((unsigned int*)(offset.data()+sizeof(unsigned int))); //the second uint
        }

        unsigned int offset_size() {
            return sizeof(unsigned int) + sizeof(unsigned int);
        }

    public:
        ByteArray make_offset(unsigned int block_num, unsigned int bytes_off) {
            ByteArray ba_block_num((uint8_t*)&block_num, (uint8_t*)&block_num + sizeof(block_num));
            ByteArray ba_off_from_start((uint8_t*)&bytes_off, (uint8_t*)&bytes_off + sizeof(bytes_off));
            //concatenate the two values
            ba_block_num.insert(ba_block_num.end(), ba_off_from_start.begin(), ba_off_from_start.end());
            return ba_block_num;
        }

        data_node(unsigned int block_num) {
            block_num_ = block_num;
            free_bytes_ = FIXED_DATA_NODE_BYTE_SIZE - sizeof(unsigned int) - sizeof(unsigned int);
            data_.resize(FIXED_DATA_NODE_BYTE_SIZE);
        }

        unsigned int get_block_num() {
            return block_num_;
        }

        ByteArray serialize_data() {
            ByteArray header = make_offset(block_num_, free_bytes_);
            std::copy(header.begin(), header.end(), data_.begin());
            return data_;
        }

        void deserialize_data(ByteArray& inData) {
            block_num_ = offset_to_block_num(inData);
            free_bytes_ = offset_to_bytes_off(inData);
            data_ = inData;
        }

        void deserialize_block_num_from_offset(ByteArray& offset) {
            block_num_ = offset_to_block_num(offset);
        }

        void deserialize_original_encrypted_data_id(pstate::StateBlockId& id) {
            originalEncryptedDataNodeId_ = id;
            SAFE_LOG(PDO_LOG_DEBUG, "deserialized original data id: %s", ByteArrayToHexEncodedString(originalEncryptedDataNodeId_).c_str());
        }

        pstate::StateBlockId serialize_id() {
            pstate::StateBlockId retId = originalEncryptedDataNodeId_;
            SAFE_LOG(PDO_LOG_DEBUG, "serialized id: %s", ByteArrayToHexEncodedString(retId).c_str());
            return retId;
        }

        unsigned int free_bytes() {
            return free_bytes_;
        }

        bool enough_space_available(bool continue_writing) {
            if(continue_writing) {
                return free_bytes_ >= 1;
            }
            //else
            return free_bytes_ >= sizeof(size_t) + 1;
        }

        ByteArray write(ByteArray& buffer, bool continue_writing) {
            //check that there is enough space to write
            pdo::error::ThrowIf<pdo::error::RuntimeError>(
                ! enough_space_available(continue_writing), "data node, not enough space to write");

            //compute cursor where to start writing
            unsigned int cursor = data_.size() - free_bytes_;
            //compute return offset
            ByteArray retOffset = make_offset(block_num_, cursor);

            //write the buffer size if necessary
            if(!continue_writing) {
                size_t buffer_size = buffer.size();
                ByteArray ba_buffer_size((uint8_t*)&buffer_size, (uint8_t*)&buffer_size+sizeof(buffer_size));
                SAFE_LOG(PDO_LOG_DEBUG, "writing buffer size: %s", ByteArrayToHexEncodedString(ba_buffer_size).c_str());
                std::copy(ba_buffer_size.begin(), ba_buffer_size.end(), data_.begin() + cursor);
                cursor += ba_buffer_size.size();
                free_bytes_ -= ba_buffer_size.size();
            }

            //write as much buffer as possible
            unsigned int bytes_to_write = (free_bytes_ > buffer.size() ? buffer.size() : free_bytes_);
            SAFE_LOG(PDO_LOG_DEBUG, "before write: free bytes %u, bytes left to write %u, written bytes %u", free_bytes_, buffer.size(), bytes_to_write);
            std::copy(buffer.begin(), buffer.begin() + bytes_to_write, data_.begin() + cursor);
            free_bytes_ -= bytes_to_write;

            //erase written bytes from original buffer
            //(if there are some left, another write will be necessary, using the continue_writing flag)
            buffer.erase(buffer.begin(), buffer.begin() + bytes_to_write);
            SAFE_LOG(PDO_LOG_DEBUG, "after write: free bytes %u, bytes left to write %u, written bytes %u", free_bytes_, buffer.size(), bytes_to_write);

            //return the offset
            SAFE_LOG(PDO_LOG_DEBUG, "write returning offset: %u %u", offset_to_block_num(retOffset), offset_to_bytes_off(retOffset));
            return retOffset;
        }

        unsigned int read(ByteArray& offset, ByteArray& outBuffer, bool continue_reading, unsigned int continue_reading_bytes) {
            //point cursor at beginning of data
            unsigned int cursor = offset_size();
            unsigned int total_bytes_to_read = continue_reading_bytes;
            if(!continue_reading) {
                //the provided offset must contain the block num of the current data node
                pdo::error::ThrowIf<pdo::error::ValueError>(
                    offset_to_block_num(offset) != block_num_, "data node, block num mismatch in offset");
                SAFE_LOG(PDO_LOG_DEBUG, "read offset: %u %u", offset_to_block_num(offset), offset_to_bytes_off(offset));
                //update the cursor
                cursor = offset_to_bytes_off(offset);
                //read the buffer size
                ByteArray ba_buffer_size(data_.begin() + cursor, data_.begin() + cursor + sizeof(size_t));
                cursor += sizeof(size_t);
                size_t buffer_size = *((size_t*)ba_buffer_size.data());
                //update the byte to read
                total_bytes_to_read = buffer_size;
                SAFE_LOG(PDO_LOG_DEBUG, "total_bytes_to_read: %u", total_bytes_to_read);
            }

            //read as much as possible in outbuffer
            unsigned int bytes_to_endof_data = data_.size() - cursor;
            unsigned int bytes_to_read = (total_bytes_to_read < bytes_to_endof_data ? total_bytes_to_read : bytes_to_endof_data);
            pdo::error::ThrowIf<pdo::error::ValueError>(
                    bytes_to_read + cursor > data_.size(), "data node, bytes_to_read overflows");
            ByteArray d(data_.begin() + cursor, data_.begin() + cursor + bytes_to_read);
            outBuffer.insert(outBuffer.end(), d.begin(), d.end());
            //update to total bytes that are still left to read
            total_bytes_to_read -= bytes_to_read;
            SAFE_LOG(PDO_LOG_DEBUG, "current outbuffer size: %u; total_bytes_to_read still: %u", outBuffer.size(), total_bytes_to_read);
            return total_bytes_to_read; //if 0, read is complete, otherwise it must continue with the next data node
        }

        void load(ByteArray state_encryption_key) {
            uint8_t* block;
            size_t block_size;
            state_status_t ret;
            SAFE_LOG(PDO_LOG_DEBUG, "loading data node id: %s", ByteArrayToHexEncodedString(originalEncryptedDataNodeId_).c_str());
            ret = sebio_fetch(originalEncryptedDataNodeId_.data(), originalEncryptedDataNodeId_.size(), SEBIO_NO_CRYPTO, &block, &block_size);
            pdo::error::ThrowIf<pdo::error::ValueError>(
                ret != STATE_SUCCESS, "data node load, sebio returned an error");
            ByteArray encrypted_buffer(block, block + block_size);
            free(block); //allocated by sebio
            ByteArray decrypted_buffer = pdo::crypto::skenc::DecryptMessage(state_encryption_key, encrypted_buffer);
            SAFE_LOG(PDO_LOG_DEBUG, "encrypted and decrypted buffer size: %u %u", encrypted_buffer.size(), decrypted_buffer.size());
            deserialize_data(decrypted_buffer);
            deserialize_block_num_from_offset(decrypted_buffer);
        }

        pstate::StateBlockId unload(ByteArray state_encryption_key) {
            ByteArray b = serialize_data();
            ByteArray baEncryptedData = pdo::crypto::skenc::EncryptMessage(state_encryption_key, b);
            state_status_t ret = sebio_evict(baEncryptedData.data(), baEncryptedData.size(), SEBIO_NO_CRYPTO, originalEncryptedDataNodeId_);
            pdo::error::ThrowIf<pdo::error::ValueError>(
                ret != STATE_SUCCESS, "data node unload, sebio returned an error");
            return originalEncryptedDataNodeId_;
        }
};

class pstate::kv_node {
    private:
        pstate::StateBlockId id_;
        pstate::StateBlockIdArray next_level_ids_;

    public:
        unsigned int depth_ = 0;
        kv_node() {}

        kv_node(unsigned int depth, StateBlockId& id, ByteArray& state_encryption_key) {
            depth_ = depth;
            deserialize_id(id);
            load(state_encryption_key);
        }

        void initialize(unsigned int depth) {
            //empty id
            depth_ = depth;
            id_ = pstate::StateBlockId(STATE_BLOCK_ID_LENGTH, 0);
            pstate::StateBlockId next_id = id_;
            for(int i=0; i<256; i++) { //children ids of kv node
                next_level_ids_.push_back(next_id);
            }
        }

        bool is_last_level(ByteArray& kvkey) {
            //ASSUMPTION: each depth level considers 8bits of id
            return (depth_+1 == kvkey.size());
        }

        pstate::StateBlockId serialize_id() {
            pstate::StateBlockId retId = id_;
            SAFE_LOG(PDO_LOG_DEBUG, "serialized id: %s", ByteArrayToHexEncodedString(retId).c_str());
            return retId;
        }

        void deserialize_id(ByteArray& inId) {
            id_ = inId;
        }

        ByteArray serialize_next_level_ids() {
            return pstate::StateBlockIdArray_To_ByteArray(next_level_ids_);
        }

        void deserialize_next_level_ids(ByteArray& buffer) {
            next_level_ids_ = pstate::ByteArrayToStateBlockIdArray(buffer, STATE_BLOCK_ID_LENGTH);
            for(unsigned int i=0; i<next_level_ids_.size(); i++) {
            }
        }

        pstate::StateBlockId get_next_level_id(unsigned int index) {
            return next_level_ids_[index];
        }

        bool next_level_id_exists(unsigned int index) {
            pstate::StateBlockId empty(STATE_BLOCK_ID_LENGTH, 0);
            if(next_level_ids_[index] != empty)
                return true;
            return false;
        }

        void set_next_level_id(unsigned int index, StateBlockId& id) {
            next_level_ids_[index] = id;
        }

        void load(ByteArray state_encryption_key) {
            uint8_t* block;
            size_t block_size;
            state_status_t ret;
            SAFE_LOG(PDO_LOG_DEBUG, "loading kv node id: %s", ByteArrayToHexEncodedString(id_).c_str());
            ret = sebio_fetch(id_.data(), id_.size(), SEBIO_NO_CRYPTO, &block, &block_size);
            pdo::error::ThrowIf<pdo::error::ValueError>(
                ret != STATE_SUCCESS, "statekv::init, sebio returned an error");
            ByteArray buffer(block, block + block_size);
            free(block); //allocated by sebio
            ByteArray decrypted_buffer = pdo::crypto::skenc::DecryptMessage(state_encryption_key, buffer);
            deserialize_next_level_ids(decrypted_buffer);
        }

        pstate::StateBlockId unload(ByteArray state_encryption_key) {
            ByteArray b = serialize_next_level_ids();
            ByteArray baEncryptedData = pdo::crypto::skenc::EncryptMessage(state_encryption_key, b);
            state_status_t ret = sebio_evict(baEncryptedData.data(), baEncryptedData.size(), SEBIO_NO_CRYPTO, id_);
            pdo::error::ThrowIf<pdo::error::ValueError>(
                ret != STATE_SUCCESS, "kv node unload, sebio returned an error");
            return id_;
        }
};

ByteArray pdo::state::State_KV::serialize_block_ids() {
    rootNode_->ClearChildren();
    for(unsigned int i=0; i<blockIds_.size(); i++) {
        rootNode_->AppendChildId(blockIds_[i]);
        SAFE_LOG(PDO_LOG_DEBUG, "root block child %u id: %s", i, ByteArrayToHexEncodedString(blockIds_[i]).c_str());
    }
    rootNode_->BlockifyChildren();
    return rootNode_->GetBlock();
}

void pdo::state::State_KV::deserialize_block_ids() {
    rootNode_->UnBlockifyChildren();
    pstate::StateBlockIdRefArray refArray = rootNode_->GetChildrenBlocks();
    blockIds_ = StateBlockIdRefArray_To_StateBlockIdArray(refArray);
}

void pdo::state::State_KV::update_block_id(pstate::StateBlockId& prevId, pstate::StateBlockId& newId) {
    std::replace(blockIds_.begin(), blockIds_.end(), prevId, newId);
}

void pdo::state::State_KV::add_block_id(pstate::StateBlockId& id) {
    blockIds_.push_back(id);
}

void pdo::state::State_KV::add_kvblock_id(pstate::StateBlockId& id) {
    //new kv nodes are after the first one
    //RATIONALE: for convention, the first one is the search root kv node,
    //           the last one is the non filled-up data node
    blockIds_.insert(blockIds_.begin() + 1, id);
}

void pdo::state::State_KV::add_datablock_id(pstate::StateBlockId& id) {
    blockIds_.push_back(id);
}

pstate::StateBlockId pdo::state::State_KV::get_datablock_id_from_datablock_num(unsigned int data_block_num) {
    //CONVENTION:   the data blocks are put in sequential order in the list,
    //              where the last block is the last appended data block, namely:
    //              last item of blockIds_ is the data block with block num last_appended_data_block_num_
    unsigned int index = blockIds_.size() - 1 - last_appended_data_block_num_ + data_block_num;
    return blockIds_[index];
}

pstate::StateBlockId pdo::state::State_KV::get_search_root_kvblock_id() {
    return blockIds_[0];
}

pstate::StateBlockId pdo::state::State_KV::get_last_datablock_id() {
    return blockIds_[blockIds_.size() - 1];
}

//###########################################################################

pdo::state::State_KV::State_KV(ByteArray& id) : Basic_KV(id) {
}

pdo::state::State_KV::State_KV(ByteArray& id, const ByteArray& key) : State_KV(id) {
    state_encryption_key_ = key;

    if(id.empty()) { //no id, create root
        SAFE_LOG(PDO_LOG_DEBUG, "statekv init: creating new state kv");
        //root node will contain the list of block/ids (first of list is search root block, last one is last data node)
        rootNode_ = new pdo::state::StateNode(*new StateBlockId(), *new StateBlock());
        //initialized search root kv node
        kv_node search_root_kv_node;
        search_root_kv_node.initialize(0);
        //StateBlockId root_kv_node_id = searchRootKVNode_->serialize_id();
        StateBlockId root_kv_node_id = search_root_kv_node.unload(state_encryption_key_);
        add_block_id(root_kv_node_id);
        //initialize first data node
        last_appended_data_block_num_ = 0;
        data_node dn(last_appended_data_block_num_);
        StateBlockId dn_id = dn.unload(state_encryption_key_);
        add_datablock_id(dn_id);
    }
    else { //retrieve main state block, search root node and last data node
        uint8_t* block;
        size_t block_size;
        state_status_t ret;
        SAFE_LOG(PDO_LOG_DEBUG, "statekv init: root id: %s", ByteArrayToHexEncodedString(id).c_str());
        ret = sebio_fetch(id.data(), id.size(), SEBIO_NO_CRYPTO, &block, &block_size);
        pdo::error::ThrowIf<pdo::error::ValueError>(
            ret != STATE_SUCCESS, "statekv::init, sebio returned an error");
        rootNode_ = new pdo::state::StateNode(*new StateBlockId(id), *new StateBlock(block, block + block_size));
        free(block); //allocated by sebio
        deserialize_block_ids();
        SAFE_LOG(PDO_LOG_DEBUG, "root block has %u ids", blockIds_.size());

        //retrieve last data block num from last appended data block
        StateBlockId lastAppendedDataNodeId = get_last_datablock_id();
        data_node dn(0);
        dn.deserialize_original_encrypted_data_id(lastAppendedDataNodeId);
        dn.load(state_encryption_key_);
        last_appended_data_block_num_ = dn.get_block_num();
    }
}

pdo::state::State_KV::State_KV(ByteArray& id, const ByteArray& key, const size_t fixed_key_size) : State_KV(id, key) {
    fixed_key_size_ = fixed_key_size;
}

pdo::state::State_KV::~State_KV() {
    StateBlockId id;
    Uninit(id);
}

void pdo::state::State_KV::Uninit(ByteArray& outId) {
    SAFE_LOG(PDO_LOG_DEBUG, "Uninit State KV");
    StateBlockId retId;
    if(rootNode_ != NULL) {
        //serialize block ids
        serialize_block_ids();
        //evict root block
        ByteArray baBlock = rootNode_->GetBlock();
        SAFE_LOG(PDO_LOG_DEBUG, "unloading root node, size %u: %s", baBlock.size(), ByteArrayToString(baBlock).c_str());;
        state_status_t ret = sebio_evict(baBlock.data(), baBlock.size(), SEBIO_NO_CRYPTO, rootNode_->GetBlockId());
        pdo::error::ThrowIf<pdo::error::ValueError>(
            ret != STATE_SUCCESS, "kv root node unload, sebio returned an error");
        //output the root id
        retId = rootNode_->GetBlockId();
        outId = retId;
        delete rootNode_;
        rootNode_ = NULL;
    }
}

ByteArray pdo::state::State_KV::to_kvkey(ByteArray& key) {
    ByteArray kvKey = pdo::crypto::ComputeMessageHash(key);
    kvKey.resize(4);
    return kvKey;
}

void pdo::state::State_KV::error_on_wrong_key_size(size_t key_size) {
    pdo::error::ThrowIf<pdo::error::ValueError>(
        key_size != fixed_key_size_ && fixed_key_size_ > 0, "state kv error, using kv with different key size");
}

void pdo::state::State_KV::operate(pstate::kv_node& search_kv_node, unsigned int operation, ByteArray& kvkey, ByteArray& value) {
    pstate::StateBlockId empty_id(STATE_BLOCK_ID_LENGTH, 0);
    unsigned int next_level_index = kvkey[search_kv_node.depth_];
    SAFE_LOG(PDO_LOG_DEBUG, "Starting search depth %u index %u", search_kv_node.depth_, next_level_index);
    if(search_kv_node.is_last_level(kvkey)) {
        pstate::StateBlockId data_node_id = search_kv_node.get_next_level_id(next_level_index);
        switch(operation) {
            case 0: { //get
                if(! search_kv_node.next_level_id_exists(next_level_index)) {
                    SAFE_LOG(PDO_LOG_DEBUG, "get, no data node");
                    return;
                }
                else {
                    pstate::data_node dn(0);
                    //in last level kvnode, the next level ids are offsets to the data nodes
                    ByteArray offset = data_node_id;
                    SAFE_LOG(PDO_LOG_DEBUG, "get, offset: %s", ByteArrayToHexEncodedString(offset).c_str());
                    dn.deserialize_block_num_from_offset(offset);
                    unsigned int data_block_num = dn.get_block_num();
                    data_node_id = get_datablock_id_from_datablock_num(data_block_num);
                    SAFE_LOG(PDO_LOG_DEBUG, "get, block num: %u; data node id: %s", data_block_num, ByteArrayToHexEncodedString(data_node_id).c_str());

                    dn.deserialize_original_encrypted_data_id(data_node_id);
                    dn.load(state_encryption_key_);

                    unsigned int bytes_to_read = dn.read(offset, value, false, 0);
                    while(bytes_to_read > 0) {
                        unsigned int next_data_block_num = dn.get_block_num() + 1;
                        SAFE_LOG(PDO_LOG_DEBUG, "get, keep reading bytes: %u; next block num: %u", bytes_to_read, next_data_block_num);
                        pstate::StateBlockId next_data_node_id = get_datablock_id_from_datablock_num(next_data_block_num);
                        data_node dn(next_data_block_num);
                        dn.deserialize_original_encrypted_data_id(next_data_node_id);
                        dn.load(state_encryption_key_);
                        bytes_to_read = dn.read(offset, value, true, bytes_to_read);
                    }

                    //do nothing (no encryption since we do not modify block)
                    return;
                }
            }
            case 1: { //put
                pstate::StateBlockId last_data_node_id = get_datablock_id_from_datablock_num(last_appended_data_block_num_);
                data_node dn(0);
                dn.deserialize_original_encrypted_data_id(last_data_node_id);
                dn.load(state_encryption_key_);
                pdo::error::ThrowIf<pdo::error::ValueError>(
                    ! dn.enough_space_available(false), "operate, last data node was left without enough space");
                SAFE_LOG(PDO_LOG_DEBUG, "put, writing key in last data node id: %s", ByteArrayToHexEncodedString(last_data_node_id).c_str());
                ByteArray value_copy = value;
                ByteArray offset = dn.write(value_copy, false);
                SAFE_LOG(PDO_LOG_DEBUG, "put, offset in data node: %s", ByteArrayToHexEncodedString(offset).c_str());
                bool last_data_node_has_enough_space = dn.enough_space_available(false);
                pstate::StateBlockId new_last_data_node_id = dn.unload(state_encryption_key_);
                SAFE_LOG(PDO_LOG_DEBUG, "put, unloaded data node id: %s", ByteArrayToHexEncodedString(new_last_data_node_id).c_str());
                update_block_id(last_data_node_id, new_last_data_node_id);
                //IMPORTANT: the ids in the last level kvnodes are the "offset"'s, i.e., block_num||offset_from_origin
                search_kv_node.set_next_level_id(next_level_index, offset);
                //keep writing if necessary
                while(value_copy.size() > 0) {
                    SAFE_LOG(PDO_LOG_DEBUG, "put, keep writing bytes: %u", value_copy.size());
                    pstate::data_node dn(++last_appended_data_block_num_);
                    dn.write(value_copy, true);
                    pdo::error::ThrowIf<pdo::error::ValueError>(
                        dn.enough_space_available(true) && value_copy.size() > 0, "operate, unwritten bytes while there is free space");
                    //track whether the data node has space for a future key-value write (used later)
                    last_data_node_has_enough_space = dn.enough_space_available(false);
                    pstate::StateBlockId new_data_node_id = dn.unload(state_encryption_key_);
                    add_datablock_id(new_data_node_id);
                    SAFE_LOG(PDO_LOG_DEBUG, "appended new data node (num %u) id: %s", last_appended_data_block_num_, ByteArrayToHexEncodedString(new_data_node_id).c_str());
                }
                //leave last data node with enough space
                if(!last_data_node_has_enough_space) {
                    data_node dn(++last_appended_data_block_num_);
                    pstate::StateBlockId new_data_node_id = dn.unload(state_encryption_key_);
                    add_datablock_id(new_data_node_id);
                }
                SAFE_LOG(PDO_LOG_DEBUG, "put completed");
                return;
            }
            case 2: { //delete
                if(! search_kv_node.next_level_id_exists(next_level_index)) {
                    SAFE_LOG(PDO_LOG_DEBUG, "delete, no data node");
                }
                else {
                    search_kv_node.set_next_level_id(next_level_index, empty_id);
                    SAFE_LOG(PDO_LOG_DEBUG, "delete, data node id: %s", ByteArrayToHexEncodedString(data_node_id).c_str());
                }
                return;
            }
            default: {
                SAFE_LOG(PDO_LOG_ERROR, "operation %u unimplemented", operation);
                throw pdo::error::ValueError("kv operation unimplemented");
            }
        }
    }
    else { //kv node is NOT last level
        if(search_kv_node.next_level_id_exists(next_level_index)) {
            pstate::StateBlockId old_kv_node_id = search_kv_node.get_next_level_id(next_level_index);
            pstate::kv_node new_kv_node;
            new_kv_node.depth_ = search_kv_node.depth_ + 1;
            new_kv_node.deserialize_id(old_kv_node_id);
            new_kv_node.load(state_encryption_key_);
            operate(new_kv_node, operation, kvkey, value);
            pstate::StateBlockId new_kv_node_id = new_kv_node.unload(state_encryption_key_);
            if(new_kv_node_id != old_kv_node_id) {
                search_kv_node.set_next_level_id(next_level_index, new_kv_node_id);
                update_block_id(old_kv_node_id, new_kv_node_id);
            }
            SAFE_LOG(PDO_LOG_DEBUG, "kvnode id: %s --> %s",
                ByteArrayToHexEncodedString(old_kv_node_id).c_str(),
                ByteArrayToHexEncodedString(new_kv_node_id).c_str());
            return;
        }
        else { // next kv node id does NOT exists
            if(operation != 1) {
                SAFE_LOG(PDO_LOG_DEBUG, "delete/get, kv node depth %u, no next id", search_kv_node.depth_);
                return;
            }
            //else
            kv_node new_kv_node;
            new_kv_node.initialize(search_kv_node.depth_ + 1);
            operate(new_kv_node, operation, kvkey, value);
            pstate::StateBlockId new_kv_node_id = new_kv_node.unload(state_encryption_key_);
            SAFE_LOG(PDO_LOG_DEBUG, "added new kvnode id: %s", ByteArrayToHexEncodedString(new_kv_node_id).c_str());
            search_kv_node.set_next_level_id(next_level_index, new_kv_node_id);
            add_kvblock_id(new_kv_node_id);
            return;
        }
    }
}

ByteArray pdo::state::State_KV::Get(ByteArray& key) {
    //hash the key and the first 32/64 bits
    ByteArray kvkey = key;

    //initialize search root kv node
    StateBlockId search_kv_node_id = get_search_root_kvblock_id();
    kv_node search_kv_node(0, search_kv_node_id, state_encryption_key_);

    //perform operation
    ByteArray value;
    error_on_wrong_key_size(kvkey.size());
    operate(search_kv_node, 0, kvkey, value);

    //update search root kv node
    pstate::StateBlockId new_search_kv_node_id = search_kv_node.unload(state_encryption_key_);
    update_block_id(search_kv_node_id, new_search_kv_node_id);

    return value;
}

void pdo::state::State_KV::Put(ByteArray& key, ByteArray& value) {
    //hash the key and the first 32/64 bits
    ByteArray kvkey = key;

    //initialize search root kv node
    StateBlockId search_kv_node_id = get_search_root_kvblock_id();
    kv_node search_kv_node(0, search_kv_node_id, state_encryption_key_);

    //perform operation
    error_on_wrong_key_size(kvkey.size());
    operate(search_kv_node, 1, kvkey, value);

    //update search root kv node
    pstate::StateBlockId new_search_kv_node_id = search_kv_node.unload(state_encryption_key_);
    update_block_id(search_kv_node_id, new_search_kv_node_id);
}

void pdo::state::State_KV::Delete(ByteArray& key) {
    ByteArray kvkey = key;

    //initialize search root kv node
    StateBlockId search_kv_node_id = get_search_root_kvblock_id();
    kv_node search_kv_node(0, search_kv_node_id, state_encryption_key_);

    //perform operation
    ByteArray value;
    error_on_wrong_key_size(kvkey.size());
    operate(search_kv_node, 2, kvkey, value);

    //update search root kv node
    pstate::StateBlockId new_search_kv_node_id = search_kv_node.unload(state_encryption_key_);
    update_block_id(search_kv_node_id, new_search_kv_node_id);
}
