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
#include <map>

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::map<std::string, std::string> contract_verify_secrets(
    const std::string& sealedSignupData, /* base64 encoded string */
    const std::string& contractId,
    const std::string& contractCreatorId, /* contract creators verifying key */
    const std::string& serializedSecretList); /* json */

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::string contract_handle_contract_encoded_request(
    const std::string& sealed_signup_data, /* base64 encoded string */
    const std::string& encrypted_session_key, /* base64 encoded string */
    const std::string& serialized_request /* base64 encoded string */
    );

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::vector<uint8_t> contract_handle_contract_request(
    const std::string& sealedSignupData,
    const std::vector<uint8_t>& encryptedSessionKey,
    const std::vector<uint8_t>& serializedRequest
    );

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::vector<uint8_t> initialize_contract_state(
    const std::string& sealedSignupData,
    const std::vector<uint8_t>& encryptedSessionKey,
    const std::vector<uint8_t>& serializedRequest
    );
