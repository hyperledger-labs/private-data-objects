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

#include <map>
#include <string>

#include "crypto.h"

#include "contract_request.h"
#include "contract_state.h"
#include "enclave_data.h"
#include "interpreter_kv.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class ContractResponse
{
protected:
    ByteArray SerializeForSigning(void) const;
    ByteArray ComputeSignature(const EnclaveData& enclave_data) const;

    std::string contract_id_;
    std::string creator_id_;
    std::string channel_verifying_key_;
    ByteArray contract_code_hash_;
    ByteArray contract_message_hash_;
    pdo::state::StateBlockId input_block_id_;
    pdo::state::StateBlockId output_block_id_;
    bool contract_initializing_;

public:
    std::map<std::string, std::string> dependencies_;
    std::string result_;
    bool operation_succeeded_;
    bool state_changed_;

    ContractResponse(
        const ContractRequest& request,
        const ContractState& contract_state,
        const std::map<std::string, std::string>& dependencies,
        const std::string& result,
        const pdo::state::StateBlockId& output_state_hash);

    ContractResponse(
        const ContractRequest& request,
        const ContractState& contract_state,
        const std::string& result);

    ByteArray SerializeAndEncrypt(
        const ByteArray& session_key, const EnclaveData& enclave_data) const;
};
