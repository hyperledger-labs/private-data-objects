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
#include  <msgpack/msgpack.hpp>

using namespace std;

namespace ccf
{
  struct ProvisioningKeysToSecretMap
  {
    string pspk;
    string encrypted_secret;

    MSGPACK_DEFINE(pspk, encrypted_secret);
  };

  inline void to_json(nlohmann::json& j, const ProvisioningKeysToSecretMap& prov_map)
  {
    j["pspk"] = prov_map.pspk;
    j["encrypted_secret"] = prov_map.encrypted_secret;
  }

  inline void from_json(const nlohmann::json& j, ProvisioningKeysToSecretMap& prov_map)
  {
    prov_map.pspk = j["pspk"].get<string>();
    prov_map.encrypted_secret = j["encrypted_secret"].get<string>();
  }


  struct ContractEnclaveInfo
  {
    string contract_enclave_id;
    string contract_id;
    string encrypted_state_encryption_key;
    string signature; // this is the enclave signature for the add enclave to contract transaction
    std::vector<ProvisioningKeysToSecretMap> provisioning_key_state_secret_pairs;

    MSGPACK_DEFINE(contract_enclave_id, contract_id, encrypted_state_encryption_key, signature, provisioning_key_state_secret_pairs);
  };

  inline void to_json(nlohmann::json& j, const ContractEnclaveInfo& contract_enclave_info)
  {
    j["contract_enclave_id"] = contract_enclave_info.contract_enclave_id;
    j["contract_id"] = contract_enclave_info.contract_id;
    j["encrypted_state_encryption_key"] = contract_enclave_info.encrypted_state_encryption_key;
    j["signature"] = contract_enclave_info.signature;
    j["provisioning_key_state_secret_pairs"] = contract_enclave_info.provisioning_key_state_secret_pairs;
  }

  inline void from_json(const nlohmann::json& j, ContractEnclaveInfo& contract_enclave_info)
  {
    contract_enclave_info.contract_enclave_id = j["contract_enclave_id"].get<string>();
    contract_enclave_info.contract_id = j["contract_id"].get<string>();
    contract_enclave_info.encrypted_state_encryption_key = j["encrypted_state_encryption_key"].get<string>();
    contract_enclave_info.signature = j["signature"].get<string>();
    contract_enclave_info.provisioning_key_state_secret_pairs = \
            j["provisioning_key_state_secret_pairs"].get<vector<ProvisioningKeysToSecretMap>>();
  }

  struct ContractInfo
  {
    string contract_id;
    std::vector<uint8_t> contract_code_hash;
    string contract_creator_verifying_key_PEM;
    std::vector<string> provisioning_service_ids;
    std::vector<ContractEnclaveInfo> enclave_info;
    std::vector<uint8_t> current_state_hash;
    bool is_active;

    MSGPACK_DEFINE(contract_id, contract_code_hash, contract_creator_verifying_key_PEM, \
         provisioning_service_ids, enclave_info, current_state_hash, is_active);
  };

  struct Register_contract {
    struct In {
      std::vector<uint8_t> contract_code_hash;
      string contract_creator_verifying_key_PEM;
      string nonce; // used while generating signature
      std::vector<uint8_t> signature;
      string contract_id;
      std::vector<string> provisioning_service_ids;
    };
  };

  struct Add_enclave {
    struct In {
      string contract_id;
      string enclave_info; //json string
      std::vector<uint8_t> signature;
    };
  };


  struct Verify_contract {
    struct In{
      string contract_id;
    };

    struct Out {
      string contract_id;
      string contract_code_hash;
      string pdo_contract_creator_pem_key;
      std::vector<string> provisioning_service_ids;
      string enclaves_info; //json string
      string signature;
    };
   };


  DECLARE_JSON_TYPE(Register_contract::In);
  DECLARE_JSON_REQUIRED_FIELDS(Register_contract::In, contract_code_hash, contract_creator_verifying_key_PEM, nonce, \
    signature, contract_id, provisioning_service_ids);

  DECLARE_JSON_TYPE(Add_enclave::In);
  DECLARE_JSON_REQUIRED_FIELDS(Add_enclave::In, contract_id, \
    enclave_info, signature);

  DECLARE_JSON_TYPE(Verify_contract::In);
  DECLARE_JSON_REQUIRED_FIELDS(Verify_contract::In, contract_id);

  DECLARE_JSON_TYPE(Verify_contract::Out);
  DECLARE_JSON_REQUIRED_FIELDS(Verify_contract::Out, contract_id, contract_code_hash, pdo_contract_creator_pem_key, \
    provisioning_service_ids, enclaves_info, signature);

}