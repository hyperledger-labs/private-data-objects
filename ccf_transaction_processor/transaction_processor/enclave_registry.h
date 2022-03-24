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

  // Kv store value data structure for enclave registry
  struct EnclaveInfo {
      string verifying_key;
      string encryption_key;
      string proof_data;
      string enclave_persistent_id;
      string registration_block_context;
      string organizational_info;
      string EHS_verifying_key;
  };

  DECLARE_JSON_TYPE(EnclaveInfo);
  DECLARE_JSON_REQUIRED_FIELDS(EnclaveInfo,
    verifying_key, 
    encryption_key, 
    proof_data, 
    enclave_persistent_id, 
    registration_block_context, 
    organizational_info, 
    EHS_verifying_key);

  //schema definition for rpcs
  struct Register_enclave {
    struct In {
      string verifying_key;
      string encryption_key;
      string proof_data;
      string enclave_persistent_id;
      string registration_block_context;
      string organizational_info;
      string EHS_verifying_key;
      vector<uint8_t> signature;
    };
  };

  struct Verify_enclave {
    struct In {
      string enclave_id; //enclave_id
    };

    struct Out {
      string verifying_key;
      string encryption_key;
      string proof_data;
      string last_registration_block_context;
      string owner_id;
      string signature;
    };
  };

  DECLARE_JSON_TYPE(Register_enclave::In);
  DECLARE_JSON_REQUIRED_FIELDS(Register_enclave::In, verifying_key, encryption_key, proof_data, enclave_persistent_id, \
    registration_block_context, organizational_info, EHS_verifying_key, signature);

  DECLARE_JSON_TYPE(Verify_enclave::In);
  DECLARE_JSON_REQUIRED_FIELDS(Verify_enclave::In, enclave_id);

  DECLARE_JSON_TYPE(Verify_enclave::Out);
  DECLARE_JSON_REQUIRED_FIELDS(Verify_enclave::Out, verifying_key, encryption_key, proof_data, last_registration_block_context, \
    owner_id, signature);
}
