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

#include "pdo_error.h"
#include "types.h"

#include <string>
#include <stdlib.h>

namespace pdo
{
    namespace enclave_api
    {
        namespace contract
        {

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
	    size_t EncryptedContractKeySize(
	        size_t contractIdSize,
	        int enclaveIndex
	        );

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            pdo_err_t VerifySecrets(
                const Base64EncodedString& inSealedEnclaveData,
                const std::string& inContractId,
                const std::string& inContractCreatorId, /* contract creator's verifying key */
                const std::string& inSerializedSecretList, /* json */
                Base64EncodedString& outEncryptedContractKey,
                Base64EncodedString& outContractKeySignature,
                int enclaveIndex
                );

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            pdo_err_t HandleContractRequest(
                const Base64EncodedString& inSealedEnclaveData,
                const ByteArray& inEncryptedSessionKey,
                const ByteArray& inSerializedRequest,
                uint32_t& outResponseIdentifier,
                size_t& outSerializedResponseSize,
                int enclaveIndex
                );

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            pdo_err_t InitializeContractState(
                const Base64EncodedString& inSealedEnclaveData,
                const ByteArray& inEncryptedSessionKey,
                const ByteArray& inSerializedRequest,
                uint32_t& outResponseIdentifier,
                size_t& outSerializedResponseSize,
                int enclaveIndex
                );

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            pdo_err_t GetSerializedResponse(
                const Base64EncodedString& inSealedEnclaveData,
                const uint32_t inResponseIdentifier,
                const size_t inSerializedResponseSize,
                ByteArray& outSerializedResponse,
                int enclaveIndex
                );

        } /* contract */
    }     /* enclave_api */
}         /* pdo */
