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

#include "state.h"

namespace pstate = pdo::state;

void pdo::state::block_warehouse::serialize_block_ids(pdo::state::StateNode& node)
{
    node.ClearChildren();
    for (unsigned int i = 0; i < blockIds_.size(); i++)
    {
        node.AppendChildId(blockIds_[i]);
    }
    node.BlockifyChildren(state_encryption_key_);
}

void pdo::state::block_warehouse::deserialize_block_ids(pdo::state::StateNode& node)
{
    node.UnBlockifyChildren(state_encryption_key_);
    blockIds_ = node.GetChildrenBlocks();
}

void pdo::state::block_warehouse::update_datablock_id(
    unsigned int data_block_num, pdo::state::StateBlockId& newId)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        newId.size() != STATE_BLOCK_ID_LENGTH, "bad block id");

    unsigned int index = data_block_num;
    blockIds_[index] = newId;
}

void pdo::state::block_warehouse::add_block_id(pstate::StateBlockId& id)
{
    pdo::error::ThrowIf<pdo::error::RuntimeError>(
        id.size() != STATE_BLOCK_ID_LENGTH, "bad block id");

    try
    {
        blockIds_.push_back(id);
    }
    catch (const std::exception& e)
    {
        SAFE_LOG_EXCEPTION("block_warehouse::add_block_id");
        throw;
    }
}

void pdo::state::block_warehouse::remove_empty_block_ids()
{
    StateBlockId emptyId(STATE_BLOCK_ID_LENGTH, 0);
    unsigned int i = 0;
    while (i < blockIds_.size())
    {
        if (blockIds_[i] == emptyId)
        {
            blockIds_.erase(blockIds_.begin() + i);
        }
        else
            i++;
    }
}

void pdo::state::block_warehouse::remove_block_id_from_datablock_num(unsigned int data_block_num)
{
    unsigned int index = data_block_num;
    blockIds_.erase(blockIds_.begin() + index);
}

void pdo::state::block_warehouse::get_datablock_id_from_datablock_num(
    unsigned int data_block_num, pdo::state::StateBlockId& outId)
{
    // CONVENTION:  the data blocks are put in sequential order in the list,
    //              where the last block is the last appended data block
    unsigned int index = data_block_num;
    outId = blockIds_[index];
}

unsigned int pdo::state::block_warehouse::get_root_block_num()
{
    return 0;  // convention
}

unsigned int pdo::state::block_warehouse::get_last_block_num()
{
    return blockIds_.size() - 1;
}

