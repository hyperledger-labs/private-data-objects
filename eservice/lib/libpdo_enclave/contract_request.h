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

#include <string>

#include "crypto.h"
#include "parson.h"

#include "contract_code.h"
#include "contract_message.h"
#include "contract_state.h"

class ContractResponse;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class ContractRequest
{
protected:
    enum Operation
    {
        op_unknown = -1,
        op_initialize = 0,
        op_update = 1
    };
    Operation operation_; /* either "initialize" or "update" */

    ContractResponse process_initialization_request(void);
    ContractResponse process_update_request(void);

public:
    std::string contract_id_;
    std::string creator_id_;
    ByteArray state_encryption_key_ = {};

    ContractState contract_state_;
    ContractCode contract_code_; /*  */
    ContractMessage contract_message_;

    ContractRequest(const ByteArray& session_key, const ByteArray& encrypted_request);

    bool is_initialize(void) const { return operation_ == op_initialize; };
    bool is_update(void) const { return operation_ == op_update; };

    ContractResponse process_request(void);
};
