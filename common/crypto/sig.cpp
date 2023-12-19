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
#include "error.h"

namespace pcsig = pdo::crypto::sig;
namespace Error = pdo::error;

const pcsig::sig_details_t pcsig::SigDetails[static_cast<int>(pcsig::SigCurve::CURVE_COUNT)] = {
    {pcsig::SigCurve::UNDEFINED, 0, NULL, 0},
    {pcsig::SigCurve::SECP256K1, NID_secp256k1, &pdo::crypto::SHA256Hash, SHA256_DIGEST_LENGTH, 72},
    {pcsig::SigCurve::SECP384R1, NID_secp384r1, &pdo::crypto::SHA384Hash, SHA384_DIGEST_LENGTH, 104}
};

const std::map<int, pcsig::SigCurve> pcsig::NidToSigCurveMap = {
    {NID_secp256k1, pcsig::SigCurve::SECP256K1},
    {NID_secp384r1, pcsig::SigCurve::SECP384R1}
};

unsigned int pcsig::Key::MaxSigSize() const
{
    return sigDetails_.maxSigSize;
}

void pcsig::Key::SetSigDetailsFromDeserializedKey()
{
    int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(key_));
    Error::ThrowIf<Error::RuntimeError>(
        nid == NID_undef, "Crypto Error (sig::PrivateKey(const std::string& encoded): undefined nid");

    auto mSigCurve = NidToSigCurveMap.find(nid);
    Error::ThrowIf<Error::RuntimeError>(
        mSigCurve == NidToSigCurveMap.end(),
        "Crypto Error (sig::PrivateKey(const std::string& encoded):unsupported nid: " + nid);

    sigDetails_ = pcsig::SigDetails[static_cast<int>(mSigCurve->second)];
}
