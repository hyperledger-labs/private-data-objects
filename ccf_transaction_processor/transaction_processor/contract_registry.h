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

using namespace std;

namespace ccf
{
  struct ProvisioningKeysToSecretMap
  {
    string pspk;
    string encrypted_secret;
  };

  DECLARE_JSON_TYPE(ProvisioningKeysToSecretMap);
  DECLARE_JSON_REQUIRED_FIELDS(ProvisioningKeysToSecretMap, 
    pspk, 
    encrypted_secret);

  struct ContractEnclaveInfo
  {
    string contract_enclave_id;
    string contract_id;
    string encrypted_state_encryption_key;
    string signature; // this is the enclave signature for the add enclave to contract transaction
    std::vector<ProvisioningKeysToSecretMap> provisioning_key_state_secret_pairs;
  };

  DECLARE_JSON_TYPE(ContractEnclaveInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ContractEnclaveInfo,
    contract_enclave_id, 
    contract_id, 
    encrypted_state_encryption_key, 
    signature, 
    provisioning_key_state_secret_pairs);

  struct ContractInfo
  {
    string contract_id;
    std::vector<uint8_t> contract_code_hash;
    std::vector<uint8_t> contract_metadata_hash;
    string contract_creator_verifying_key_PEM;
    std::vector<string> provisioning_service_ids;
    std::vector<ContractEnclaveInfo> enclave_info;
    std::vector<uint8_t> current_state_hash;
    bool is_active;
  };

  DECLARE_JSON_TYPE(ContractInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ContractInfo,
    contract_id,
    contract_code_hash,
    contract_metadata_hash,
    contract_creator_verifying_key_PEM,
    provisioning_service_ids,
    enclave_info,
    current_state_hash,
    is_active);

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

  struct Get_contract_provisioning_info {
    struct In{
      string contract_id;
    };

    struct Out {
      string pdo_contract_creator_pem_key;
      std::vector<string> provisioning_service_ids;
      std::vector<ContractEnclaveInfo> enclaves_info;
      string signature;
    };
   };

  struct Get_contract_info {
    struct In{
      string contract_id;
    };

    struct Out {
      string pdo_contract_creator_pem_key;
      string contract_code_hash;
      string metadata_hash;
      string signature;
    };
   };

  DECLARE_JSON_TYPE(Register_contract::In);
  DECLARE_JSON_REQUIRED_FIELDS(Register_contract::In, contract_code_hash, contract_creator_verifying_key_PEM, nonce, \
    signature, contract_id, provisioning_service_ids);

  DECLARE_JSON_TYPE(Add_enclave::In);
  DECLARE_JSON_REQUIRED_FIELDS(Add_enclave::In, contract_id, \
    enclave_info, signature);

  DECLARE_JSON_TYPE(Get_contract_provisioning_info::In);
  DECLARE_JSON_REQUIRED_FIELDS(Get_contract_provisioning_info::In, contract_id);

  DECLARE_JSON_TYPE(Get_contract_provisioning_info::Out);
  DECLARE_JSON_REQUIRED_FIELDS(Get_contract_provisioning_info::Out, pdo_contract_creator_pem_key, \
                               provisioning_service_ids, enclaves_info, signature);

  DECLARE_JSON_TYPE(Get_contract_info::In);
  DECLARE_JSON_REQUIRED_FIELDS(Get_contract_info::In, contract_id);

  DECLARE_JSON_TYPE(Get_contract_info::Out);
  DECLARE_JSON_REQUIRED_FIELDS(Get_contract_info::Out, pdo_contract_creator_pem_key, contract_code_hash, metadata_hash, signature);

}
