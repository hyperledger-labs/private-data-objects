/* Copyright 2020 Intel Corporation
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

#include "ds/json.h"
#include "ds/buffer.h"
#include <msgpack/msgpack.hpp>

using namespace std;

namespace ccf
{

  struct ContractStateDependecy {
    string contract_id;
    vector<uint8_t> state_hash;
    string state_hash_for_sign;

    MSGPACK_DEFINE(contract_id, state_hash, state_hash_for_sign);
  };

  inline void to_json(nlohmann::json& j, const ContractStateDependecy& contract_dep)
  {
    j["contract_id"] = contract_dep.contract_id;
    j["state_hash"] = contract_dep.state_hash;
    j["state_hash_for_sign"] = contract_dep.state_hash_for_sign;
  }

  inline void from_json(const nlohmann::json& j, ContractStateDependecy& contract_dep)
  {
    contract_dep.contract_id = j["contract_id"].get<string>();
    contract_dep.state_hash = j["state_hash"].get<vector<uint8_t>>();
    contract_dep.state_hash_for_sign = j["state_hash_for_sign"].get<string>();
  }

  struct ContractStateInfo {
    vector<uint8_t> transaction_id;
    vector<uint8_t> previous_state_hash;
    vector<uint8_t> message_hash;
    vector<ContractStateDependecy> dependency_list;

    MSGPACK_DEFINE(transaction_id, previous_state_hash, message_hash, dependency_list);
  };

  struct StateUpdateInfo {
    string contract_id;
    vector<uint8_t> current_state_hash;
    vector<uint8_t> previous_state_hash;
    vector<uint8_t> message_hash;
    vector<ContractStateDependecy> dependency_list;

    MSGPACK_DEFINE(contract_id, current_state_hash, previous_state_hash, message_hash, dependency_list);
  };

  inline void to_json(nlohmann::json& j, const StateUpdateInfo& state_update_info)
  {
    j["contract_id"] = state_update_info.contract_id;
    j["current_state_hash"] = state_update_info.current_state_hash;
    j["previous_state_hash"] = state_update_info.previous_state_hash;
    j["message_hash"] = state_update_info.message_hash;
    j["dependency_list"] = state_update_info.dependency_list;
  }

  inline void from_json(const nlohmann::json& j, StateUpdateInfo& state_update_info)
  {
    state_update_info.contract_id = j["contract_id"].get<string>();
    state_update_info.current_state_hash = j["current_state_hash"].get<vector<uint8_t>>();
    state_update_info.previous_state_hash = j["previous_state_hash"].get<vector<uint8_t>>();
    state_update_info.message_hash = j["message_hash"].get<vector<uint8_t>>();
    state_update_info.dependency_list = \
            j["dependency_list"].get<vector<ContractStateDependecy>>();
  }

  struct Update_contract_state {
    struct In{
      string verb;
      string contract_enclave_id;
      vector<uint8_t> contract_enclave_signature;
      vector<uint8_t> signature;
      vector<uint8_t> nonce;
      string state_update_info; //json string
    };

  };

  struct Get_current_state_info {
      struct In{
          string contract_id;

      };

      struct Out {
          string state_hash;
          bool is_active;
          string signature;
      };
  };

  struct Get_state_details {
      struct In {
          string contract_id;
          vector<uint8_t> state_hash;
      };

      struct Out {
          string transaction_id;
          string previous_state_hash;
          string message_hash;
          string dependency_list;  //json string
          string signature;
      };
  };

  // check input complies with schema
  DECLARE_JSON_TYPE(Update_contract_state::In);
  DECLARE_JSON_REQUIRED_FIELDS(Update_contract_state::In, verb, contract_enclave_id, \
    contract_enclave_signature, signature, nonce, state_update_info);

  DECLARE_JSON_TYPE(Get_current_state_info::In);
  DECLARE_JSON_REQUIRED_FIELDS(Get_current_state_info::In, contract_id);

  DECLARE_JSON_TYPE(Get_current_state_info::Out);
  DECLARE_JSON_REQUIRED_FIELDS(Get_current_state_info::Out, state_hash, is_active, signature);

  DECLARE_JSON_TYPE(Get_state_details::In);
  DECLARE_JSON_REQUIRED_FIELDS(Get_state_details::In, contract_id, state_hash);

  DECLARE_JSON_TYPE(Get_state_details::Out);
  DECLARE_JSON_REQUIRED_FIELDS(Get_state_details::Out, transaction_id, previous_state_hash,\
   message_hash, dependency_list, signature);

}