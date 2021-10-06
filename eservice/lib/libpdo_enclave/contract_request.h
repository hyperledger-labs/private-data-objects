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

#include <memory>
#include <string>

#include "crypto.h"
#include "parson.h"

#include "contract_code.h"
#include "contract_message.h"
#include "contract_state.h"
#include "contract_worker.h"

class ContractResponse;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class ContractRequest
{
protected:
    void parse_common_properties(const JSON_Object* request_object);

public:
    std::string contract_id_;
    std::string creator_id_;
    ByteArray state_encryption_key_ = {};
    ByteArray contract_id_hash_ = {};

    ContractCode contract_code_; /*  */
    ContractMessage contract_message_;

    ContractWorker *worker_ = NULL;

    ContractRequest(ContractWorker* worker);

    virtual std::shared_ptr<ContractResponse> process_request(ContractState& contract_state) = 0;
};

class InitializeStateRequest : public ContractRequest
{
public:
    InitializeStateRequest(
        const ByteArray& session_key,
        const ByteArray& encrypted_request,
        ContractWorker* worker);

    std::shared_ptr<ContractResponse> process_request(ContractState& contract_state);
};

class UpdateStateRequest : public ContractRequest
{
public:
    ByteArray code_hash_ = {};
    ByteArray input_state_hash_ = {};

    UpdateStateRequest(
        const ByteArray& session_key,
        const ByteArray& encrypted_request,
        ContractWorker* worker);

    std::shared_ptr<ContractResponse> process_request(ContractState& contract_state);
};
