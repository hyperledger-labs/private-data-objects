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

#include <stdlib.h>

#include "types.h"
#include <string>

namespace pdo
{
    namespace enclave_api
    {
        namespace enclave_data
        {
            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            pdo_err_t CreateEnclaveData(
                StringArray& outPublicEnclaveData,
                Base64EncodedString& outSealedEnclaveData,
                Base64EncodedString& outEnclaveQuote
                );

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            pdo_err_t UnsealEnclaveData(
                const Base64EncodedString& inSealedEnclaveData,
                StringArray& outPublicEnclaveData
                );

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            pdo_err_t CreateSealedSecret(
                const size_t secret_len,
                Base64EncodedString& outSealedSecret
                );


            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            pdo_err_t UnsealSecret(
                const Base64EncodedString& inSealedSecret,
                HexEncodedString& outPlainSecret
                );

            // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            pdo_err_t GenerateEnclaveSecret(
                const Base64EncodedString& inSealedEnclaveData,
                const Base64EncodedString& inSealedSecret,
                const std::string& inContractId,
                const std::string& inOpk,
                const std::string& inEnclaveInfo,
                Base64EncodedString& ouSignedSecret
                );


        } /* secret namespace */

    } /* enclave_api namespace */

} /* pdo namespace */
