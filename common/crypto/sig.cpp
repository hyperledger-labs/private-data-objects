/* Copyright 2022 Intel Corporation
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

#include <map>
#include <openssl/sha.h>
#include "sig.h"
#include "hash.h"

namespace pdo
{
namespace crypto
{
    namespace sig
    {
        const sig_details_t SigDetails[static_cast<int>(SigCurve::CURVE_COUNT)] = {
            {SigCurve::UNDEFINED, 0, NULL, 0},
            {SigCurve::SECP256K1, NID_secp256k1, &pdo::crypto::SHA256Hash, SHA256_DIGEST_LENGTH, 72},
            {SigCurve::SECP384R1, NID_secp384r1, &pdo::crypto::SHA384Hash, SHA384_DIGEST_LENGTH, 104}
        };

        const std::map<int, SigCurve> NidToSigCurveMap = {
            {NID_secp256k1, SigCurve::SECP256K1},
            {NID_secp384r1, SigCurve::SECP384R1}
        };
    }
}
}
