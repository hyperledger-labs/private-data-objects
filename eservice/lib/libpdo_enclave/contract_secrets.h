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

#include <string.h>

#include "crypto.h"
#include "hex_string.h"
#include "types.h"

#include "enclave_data.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#define SECRET_SIZE pdo::crypto::constants::SYM_KEY_LEN
#define ENCODED_SECRET_SIZE HEX_STRING_SIZE(SECRET_SIZE)
#define SECRET_SIGNATURE_SIZE pdo::crypto::constants::MAX_SIG_SIZE
#define ENCODED_SECRET_SIGNATURE_SIZE HEX_STRING_SIZE(SECRET_SIGNATURE_SIZE)

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t CreateEnclaveStateEncryptionKey(const EnclaveData& enclave_data,
    const std::string& inContractId,
    const std::string& inCreatorId,
    const std::string& inSerializedSecretList,
    ByteArray& contractStateEncryptionKey,
    ByteArray& message);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray EncryptStateEncryptionKey(
    const std::string& inContractId, const ByteArray& inContractStateEncryptionKey);

Base64EncodedString EncryptAndEncodeStateEncryptionKey(
    const std::string& inContractId, const ByteArray& inContractStateEncryptionKey);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray DecryptStateEncryptionKey(
    const std::string& inContractId, const ByteArray& inEncryptedStateEncryptionKey);

ByteArray DecodeAndDecryptStateEncryptionKey(const std::string& inContractId,
    const Base64EncodedString& inEncodedEncryptedStateEncryptionKey);
