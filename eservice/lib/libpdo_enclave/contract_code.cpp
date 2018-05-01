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

#include <string>
#include <vector>

#include "error.h"
#include "pdo_error.h"

#include "crypto.h"
#include "parson.h"

#include "contract_code.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Request format for create and send methods
//
//     "ContractCode" :
//     {
//         "Code" : "<string>",
//         "Name" : "<string>"
//         "Nonce" : "<string>"
//     }
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractCode::Unpack(const JSON_Object* object)
{
    const char* pvalue = nullptr;

    // contract code
    pvalue = json_object_dotget_string(object, "Code");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve Code");
    code_.assign(pvalue);

    pvalue = json_object_dotget_string(object, "Name");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve Name");
    name_.assign(pvalue);

    pvalue = json_object_dotget_string(object, "Nonce");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve Nonce");
    nonce_.assign(pvalue);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray ContractCode::SerializeForHashing(void) const
{
    ByteArray message;
    message.reserve(code_.length() + name_.length() + nonce_.length());
    std::copy(code_.begin(), code_.end(), std::back_inserter(message));
    std::copy(name_.begin(), name_.end(), std::back_inserter(message));
    std::copy(nonce_.begin(), nonce_.end(), std::back_inserter(message));

    return message;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray ContractCode::ComputeHash(void) const
{
    return pdo::crypto::ComputeMessageHash(SerializeForHashing());
}
