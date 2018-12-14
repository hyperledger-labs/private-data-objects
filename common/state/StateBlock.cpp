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

#include "StateBlock.h"

pdo::state::StateBlockIdArray pdo::state::StateBlockIdRefArray_To_StateBlockIdArray(
    pdo::state::StateBlockIdRefArray& refArray)
{
    pdo::state::StateBlockIdArray array;
    unsigned int i;
    for (i = 0; i < refArray.size(); i++)
    {
        array.push_back(*refArray[i]);
    }
    return array;
}

void pdo::state::StateBlockIdRefArray_To_StateBlockIdList(
    pdo::state::StateBlockIdRefArray& refArray, pdo::state::StateBlockIdList& outList)
{
    unsigned int i;
    for (i = 0; i < refArray.size(); i++)
    {
        outList.push_back(*refArray[i]);
    }
}

ByteArray pdo::state::StateBlockIdRefArray_To_ByteArray(pdo::state::StateBlockIdRefArray& refArray)
{
    ByteArray concatenatedIds;
    unsigned int i;
    for (i = 0; i < refArray.size(); i++)
    {
        concatenatedIds.insert(concatenatedIds.end(), (*refArray[i]).begin(), (*refArray[i]).end());
    }
    return concatenatedIds;
}

void pdo::state::StateBlockIdArray_To_ByteArray(
    pdo::state::StateBlockIdArray& array, ByteArray& outB)
{
    for (unsigned int i = 0; i < array.size(); i += 1)
    {
        outB.insert(outB.end(), array[i].begin(), array[i].end());
    }
}

void pdo::state::ByteArrayToStateBlockIdArray(
    ByteArray& b, size_t idSize, pdo::state::StateBlockIdArray& outA)
{
    for (unsigned int i = 0; i < b.size(); i += idSize)
    {
        pdo::state::StateBlockId id(b.data() + i, b.data() + i + idSize);
        outA.push_back(id);
    }
}
