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
#include "contract_state.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// See ${PDO_SOURCE_ROOT}/eservice/docs/contract.json for format
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractCode::Unpack(const JSON_Object* object)
{
    const char* pvalue = nullptr;
    JSON_Object *pobj = nullptr;
    try
    {
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

        // compilation report (might be empty)
        pobj = json_object_dotget_object(object, "CompilationReport");
        pdo::error::ThrowIf<pdo::error::ValueError>(
            !pobj, "invalid request; failed to retrieve CompilationReport");
        // if the compilation report is not empty, then unpack
        if (json_object_get_count(pobj) > 0)
            compilation_report_.Unpack(pobj);

        ComputeHash(code_hash_);
    }
    catch (std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Error while unpacking contract code; %s", e.what());
        throw;
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractCode::FetchFromState(const ContractState& state,
                                  const ByteArray& code_hash)
{
    try
    {
        {
            std::string str = "ContractCode.Code";
            ByteArray k(str.begin(), str.end());
            ByteArray v(state.state_.PrivilegedGet(k));
            pdo::error::ThrowIf<pdo::error::ValueError>(
                v.size() == 0, "contract code missing");
            code_ = ByteArrayToString(v);
        }

        {
            std::string str = "ContractCode.CompilationReport";
            ByteArray k(str.begin(), str.end());
            ByteArray v(state.state_.PrivilegedGet(k));
            pdo::error::ThrowIf<pdo::error::ValueError>(
                v.size() == 0, "contract compilation report missing");
            compilation_report_.Unpack(ByteArrayToString(v));
        }

        {
            std::string str = "ContractCode.Name";
            ByteArray k(str.begin(), str.end());
            ByteArray v(state.state_.PrivilegedGet(k));
            pdo::error::ThrowIf<pdo::error::ValueError>(
                v.size() == 0, "contract code name missing");
            name_ = ByteArrayToString(v);
        }

        {
            std::string str = "ContractCode.Nonce";
            ByteArray k(str.begin(), str.end());
            ByteArray v(state.state_.PrivilegedGet(k));
            pdo::error::ThrowIf<pdo::error::ValueError>(
                v.size() == 0, "contract code nonce missing");
            nonce_ = ByteArrayToString(v);
        }

        {
            std::string str = "ContractCode.Hash";
            ByteArray k(str.begin(), str.end());
            ByteArray v(state.state_.PrivilegedGet(k));
            pdo::error::ThrowIf<pdo::error::ValueError>(
                v.size() == 0, "contract code hash missing");
            pdo::error::ThrowIf<pdo::error::ValueError>(
                v != code_hash, "mismatched contract code hash");
            code_hash_ = v;
        }
    }
    catch (std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Error while retrieving contract code; %s", e.what());
        throw;
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractCode::SaveToState(ContractState& state)
{
    try
    {
        {
            std::string str = "ContractCode.CompilationReport";
            ByteArray k(str.begin(), str.end());
            std::string serialized_report = compilation_report_.Pack();
            ByteArray v(serialized_report.begin(), serialized_report.end());
            state.state_.PrivilegedPut(k, v);
        }

        {
            std::string str = "ContractCode.Code";
            ByteArray k(str.begin(), str.end());
            ByteArray v(code_.begin(), code_.end());
            state.state_.PrivilegedPut(k, v);
        }

        {
            std::string str = "ContractCode.Name";
            ByteArray k(str.begin(), str.end());
            ByteArray v(name_.begin(), name_.end());
            state.state_.PrivilegedPut(k, v);
        }

        {
            std::string str = "ContractCode.Nonce";
            ByteArray k(str.begin(), str.end());
            ByteArray v(nonce_.begin(), nonce_.end());
            state.state_.PrivilegedPut(k, v);
        }

        {
            std::string str = "ContractCode.Hash";
            ByteArray k(str.begin(), str.end());
            state.state_.PrivilegedPut(k, code_hash_);
        }
    }
    catch (std::exception& e)
    {
        SAFE_LOG(PDO_LOG_ERROR, "Error while storing contract code; %s", e.what());
        throw;
    }
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractCode::ComputeHash(ByteArray& final_hash) const
{
    // the hash is going to be a combination of the hash of the
    // actual code, the hash of the nonce, and the hash of the
    // compilation report if it exists. this makes it possible
    // to use the nonce plus the registered code hash to verify
    // the actual hash of the code. that means a contract can
    // check the code hash of the other end of a secure connection
    ByteArray code_message;
    code_message.reserve(code_.length() + name_.length());
    std::copy(code_.begin(), code_.end(), std::back_inserter(code_message));
    std::copy(name_.begin(), name_.end(), std::back_inserter(code_message));
    ByteArray code_hash = pdo::crypto::ComputeMessageHash(code_message);

    ByteArray nonce_message(nonce_.begin(), nonce_.end());
    ByteArray nonce_hash = pdo::crypto::ComputeMessageHash(nonce_message);

    ByteArray message;
    message.reserve(code_hash.size() + nonce_hash.size());
    std::copy(code_hash.begin(), code_hash.end(), std::back_inserter(message));
    std::copy(nonce_hash.begin(), nonce_hash.end(), std::back_inserter(message));

    // the compilation report is optional in a contract
    // if the compiler verfying key is present, we assume we have a full report
    if (! compilation_report_.CompilerVerifyingKey().empty()) {
        ByteArray report_hash;
        compilation_report_.ComputeHash(report_hash);

        message.reserve(message.size() + report_hash.size());
        std::copy(report_hash.begin(), report_hash.end(), std::back_inserter(message));
    }

    final_hash = pdo::crypto::ComputeMessageHash(message);
}
