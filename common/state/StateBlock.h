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

#include <openssl/sha.h>
#include "types.h"

#define STATE_BLOCK_ID_LENGTH SHA256_DIGEST_LENGTH

namespace pdo
{
namespace state
{
    typedef ByteArray StateBlock;
    typedef ByteArray* StateBlockRef;

    typedef ByteArray StateBlockId;
    typedef ByteArray* StateBlockIdRef;

    typedef std::vector<StateBlockId> StateBlockIdArray;
    typedef std::vector<StateBlockIdRef> StateBlockIdRefArray;

    typedef std::list<StateBlockId> StateBlockIdList;

    StateBlockIdArray StateBlockIdRefArray_To_StateBlockIdArray(StateBlockIdRefArray& refArray);
    void StateBlockIdRefArray_To_StateBlockIdList(
        StateBlockIdRefArray& refArray, StateBlockIdList& outList);
    ByteArray StateBlockIdRefArray_To_ByteArray(StateBlockIdRefArray& refArray);

    void StateBlockIdArray_To_ByteArray(StateBlockIdArray& array, ByteArray& outB);
    void ByteArrayToStateBlockIdArray(ByteArray& b, size_t idSize, StateBlockIdArray& outA);
}
}
