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
#include <openssl/ec.h>
#include <string>
#include <vector>
#include "types.h"
#include "sig.h"

namespace pdo
{
namespace crypto
{
    namespace sig
    {
        class PrivateKey;

        class PublicKey: public Key
        {
        public:
            // default constructor: UNINITIALIZED PublicKey!
            PublicKey()
            {
                key_ = nullptr;
                sigDetails_ = SigDetails[static_cast<int>(SigCurve::PDO_DEFAULT_SIGCURVE)];
            }
            // Custom curve constructor
            PublicKey(const SigCurve& sigCurve);
            // copy constructor
            // throws RuntimeError
            PublicKey(const PublicKey& publicKey);
            // move constructor
            // throws RuntimeError
            PublicKey(PublicKey&& publicKey);
            // throws RuntimeError
            PublicKey(const PrivateKey& privateKey);
            // deserializing constructor
            // throws RuntimeError, ValueError
            PublicKey(const std::string& encoded);
            ~PublicKey();
            // throws RuntimeError
            PublicKey& operator=(const PublicKey& publicKey);
            // throws RuntimeError, ValueError
            void Deserialize(const std::string& encoded);
            // throws RuntimeError
            std::string Serialize() const;
            // throws RuntimeError
            // Serialize EC point (X,Y) to hex string for Sawtooth compatibility
            // throws RuntimeError
            std::string SerializeXYToHex() const;
            // Deserialize EC point (X,Y) hex string for Sawtooth compatibility
            // throws RuntimeError, ValueError
            void DeserializeXYFromHex(const std::string& hexXY);
            // Verify signature signature.data() on message.data() and return 1 if signature is
            // valid, 0 if signature is not valid or -1 if there was an internal error
            int VerifySignature(const ByteArray& message, const ByteArray& signature) const;
            static unsigned int MaxSigSize(const std::string& encoded);
        };
    }
}
}
