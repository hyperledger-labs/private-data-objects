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

#include "StateBlock.h"
#include "types.h"

namespace pdo
{
namespace state
{
    class StateNode
    {
    protected:
        pdo::state::StateBlockId blockId_;
        pdo::state::StateBlock stateBlock_;
        pdo::state::StateBlockIdArray ChildrenArray_ = {};
        bool hasParent_ = false;

    public:
        pdo::state::StateBlockId& GetBlockId();
        pdo::state::StateBlock& GetBlock();

        void AppendChild(pdo::state::StateNode& childNode);
        void AppendChildId(StateBlockId& childId);
        void SetHasParent();
        void BlockifyChildren(const ByteArray& state_encryption_key);
        void UnBlockifyChildren(const ByteArray& state_encryption_key);
        pdo::state::StateBlockIdArray GetChildrenBlocks();
        void ClearChildren();
    };

    typedef pdo::state::StateNode State;
    typedef pdo::state::StateNode* StateNodeRef;
    typedef std::vector<pdo::state::StateNode> StateNodeArray;
}
}
