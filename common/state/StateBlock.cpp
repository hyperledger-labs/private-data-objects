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
    for(i=0; i<refArray.size(); i++) {
        array.push_back(*refArray[i]);
    }
    return array;
}

ByteArray pdo::state::StateBlockIdRefArray_To_ByteArray(
    pdo::state::StateBlockIdRefArray& refArray)
{
    ByteArray concatenatedIds;
    unsigned int i;
    for(i=0; i<refArray.size(); i++) {
        concatenatedIds.insert(concatenatedIds.end(), (*refArray[i]).begin(), (*refArray[i]).end());
    }
    return concatenatedIds;
}
