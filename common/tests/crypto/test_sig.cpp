/* Copyright 2023 Intel Corporation
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

#include "testCrypto.h"

#include <assert.h>
#include <string.h>
#include <openssl/bn.h>

#include "c11_support.h"
#include "crypto.h"
#include "crypto_shared.h"
#include "error.h"
#include "log.h"
#include "pdo_error.h"

#if _UNTRUSTED_
#include <openssl/crypto.h>
#include <stdio.h>
#else
#include "tSgxSSL_api.h"
#endif

#include "test_shared.h"

namespace pcrypto = pdo::crypto;
namespace constants = pdo::crypto::constants;

// Error handling
namespace pdo_error = pdo::error;


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static pcrypto::sig::PrivateKey CreatePrivateKey(
    pcrypto::sig::SigCurve curve,
    bool initialize);

static pcrypto::sig::PublicKey CreatePublicKey(
    pcrypto::sig::SigCurve curve,
    const pcrypto::sig::PrivateKey& private_key);

static bool test_common_constructors(pcrypto::sig::SigCurve curve);
static bool test_key_serialization(pcrypto::sig::SigCurve curve);
static bool test_assignment_operators(pcrypto::sig::SigCurve curve);
static bool test_signature(pcrypto::sig::SigCurve curve);
static bool test_bignum_constructor(pcrypto::sig::SigCurve curve);

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool SignatureTestSuite(pcrypto::sig::SigCurve sigCurve)
{
    SAFE_LOG(PDO_LOG_DEBUG,
             "SignatureTestSuite: testing signature scheme %d\n", static_cast<int>(sigCurve));

    RUNTEST(test_common_constructors(sigCurve), "ECDSA common constructors");
    RUNTEST(test_key_serialization(sigCurve), "ECDSA serialization/deserialization");
    RUNTEST(test_assignment_operators(sigCurve), "ECDSA assignment operators");
    RUNTEST(test_signature(sigCurve), "ECDSA signature verification");
    RUNTEST(test_bignum_constructor(sigCurve), "ECDSA bignum constructors");

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static bool test_common_constructors(pcrypto::sig::SigCurve curve)
{
    // Test signature schemes with non-default constructors
    // Test ECDSA key management functions

    // test curve-specific constructor
    {
        pcrypto::sig::PrivateKey private_key(curve);
        ASSERT_FALSE(private_key);

        pcrypto::sig::PublicKey public_key(curve);
        ASSERT_FALSE(public_key);
    }

    // test curve-specific constructor with key generation
    {
        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();
        ASSERT_TRUE(private_key);

        pcrypto::sig::PublicKey public_key(private_key);
        ASSERT_TRUE(public_key);
    }

    // test curve-specific public key constructor with uninitialized private key
    {
        pcrypto::sig::PrivateKey private_key(curve);
        ASSERT_FALSE(private_key);

        pcrypto::sig::PublicKey public_key(private_key);
        ASSERT_FALSE(public_key);
    }

    // test copy constructors with initialized keys
    {
        pcrypto::sig::PrivateKey private_key1(curve);
        private_key1.Generate();

        pcrypto::sig::PublicKey public_key1(private_key1);

        pcrypto::sig::PrivateKey private_key2(private_key1);
        ASSERT_TRUE(private_key2);

        pcrypto::sig::PublicKey public_key2(public_key1);
        ASSERT_TRUE(public_key2);
    }

    // test move constructors with uninitialized keys
    {
        pcrypto::sig::PrivateKey private_key1(CreatePrivateKey(curve, false));
        ASSERT_FALSE(private_key1);

        pcrypto::sig::PublicKey public_key1(CreatePublicKey(curve, private_key1));
        ASSERT_FALSE(public_key1);
    }

    // test move constructors with uninitialized keys
    {
        pcrypto::sig::PrivateKey private_key1(CreatePrivateKey(curve, true));
        ASSERT_TRUE(private_key1);

        pcrypto::sig::PublicKey public_key1(CreatePublicKey(curve, private_key1));
        ASSERT_TRUE(public_key1);
    }

    // constructors from PEM encoded keys will be tested along
    // with serialize/deserialize tests

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static bool test_key_serialization(pcrypto::sig::SigCurve curve)
{
    // Test key serialization, this will be used in later tests so
    // this test should run early

    // basic test to ensure that serialization generates a string
    {
        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();
        ASSERT_TRUE(private_key);

        const std::string serialized_private_key = private_key.Serialize();
        ASSERT_TRUE(serialized_private_key.length() > 0);

        pcrypto::sig::PublicKey public_key(private_key);
        ASSERT_TRUE(public_key);

        const std::string serialized_public_key = public_key.Serialize();
        ASSERT_TRUE(serialized_public_key.length() > 0);
    }

    // make sure that an attempt to serialize an uninitialized private
    // key throws a ValueError exception
    {
        try {
            pcrypto::sig::PrivateKey private_key(curve);
            ASSERT_FALSE(private_key);

            // this should throw an ex
            const std::string serialized_private_key = private_key.Serialize();
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::ValueError& e) {
            // this is the expected exception
        }
    }

    // make sure that an attempt to serialize an uninitialized public
    // key throws a ValueError exception
    {
        try {
            pcrypto::sig::PublicKey public_key(curve);
            ASSERT_FALSE(public_key);

            // this should throw an ex
            const std::string serialized_public_key = public_key.Serialize();
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::ValueError& e) {
            // this is the expected exception
        }
    }

    // basic test to make sure that the string generated by serialization
    // of a private key can be deserialized into a valid key
    {
        pcrypto::sig::PrivateKey private_key1(curve);
        private_key1.Generate();
        ASSERT_TRUE(private_key1);

        const std::string serialized_private_key = private_key1.Serialize();
        ASSERT_TRUE(serialized_private_key.length() > 0);

        pcrypto::sig::PrivateKey private_key2(curve);
        ASSERT_FALSE(private_key2);
        private_key2.Deserialize(serialized_private_key);
        ASSERT_TRUE(private_key2);

        // Deserialize into a key that is already initialized
        private_key1.Deserialize(serialized_private_key);
        ASSERT_TRUE(private_key1);
    }

    // basic test to make sure that the string generated by serialization
    // of a public key can be deserialized into a valid key
    {
        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();
        ASSERT_TRUE(private_key);

        pcrypto::sig::PublicKey public_key1(private_key);
        ASSERT_TRUE(public_key1);

        const std::string serialized_public_key = public_key1.Serialize();
        ASSERT_TRUE(serialized_public_key.length() > 0);

        pcrypto::sig::PublicKey public_key2(curve);
        ASSERT_FALSE(public_key2);

        public_key2.Deserialize(serialized_public_key);
        ASSERT_TRUE(public_key2);

        // Deserialize into a key that is already initialized
        public_key1.Deserialize(serialized_public_key);
        ASSERT_TRUE(public_key1);
    }

    // basic test to make sure that the string generated by serialization
    // of a private key can be deserialized into a valid key through the constructor
    {
        pcrypto::sig::PrivateKey private_key1(curve);
        private_key1.Generate();
        ASSERT_TRUE(private_key1);

        const std::string serialized_private_key = private_key1.Serialize();
        ASSERT_TRUE(serialized_private_key.length() > 0);

        pcrypto::sig::PrivateKey private_key2(serialized_private_key);
        ASSERT_TRUE(private_key2);
    }

    // basic test to make sure that the string generated by serialization
    // of a public key can be deserialized into a valid key
    {
        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();
        ASSERT_TRUE(private_key);

        pcrypto::sig::PublicKey public_key1(private_key);
        ASSERT_TRUE(public_key1);

        const std::string serialized_public_key = public_key1.Serialize();
        ASSERT_TRUE(serialized_public_key.length() > 0);

        pcrypto::sig::PublicKey public_key2(serialized_public_key);
        ASSERT_TRUE(public_key2);
    }

    // make sure the serialized string generates an equivalent private key
    {
        pcrypto::sig::PrivateKey private_key1(curve);
        private_key1.Generate();
        ASSERT_TRUE(private_key1);

        const std::string serialized_private_key1 = private_key1.Serialize();
        ASSERT_TRUE(serialized_private_key1.length() > 0);

        pcrypto::sig::PrivateKey private_key2(serialized_private_key1);
        ASSERT_TRUE(private_key2);

        const std::string serialized_private_key2 = private_key2.Serialize();
        ASSERT_TRUE(serialized_private_key2.length() > 0);
        ASSERT_TRUE(serialized_private_key2 == serialized_private_key1);
    }

    // basic test to make sure that the string generated by serialization
    // of a public key can be deserialized into a valid key
    {
        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();
        ASSERT_TRUE(private_key);

        pcrypto::sig::PublicKey public_key1(private_key);
        ASSERT_TRUE(public_key1);

        const std::string serialized_public_key1 = public_key1.Serialize();
        ASSERT_TRUE(serialized_public_key1.length() > 0);

        pcrypto::sig::PublicKey public_key2(serialized_public_key1);
        ASSERT_TRUE(public_key2);

        const std::string serialized_public_key2 = public_key2.Serialize();
        ASSERT_TRUE(serialized_public_key2.length() > 0);
        ASSERT_TRUE(serialized_public_key2 == serialized_public_key1);
    }

    // test deserialization of private with bad values
    {
        const std::string invalid_key("this is not a serialized key");

        try {
            pcrypto::sig::PrivateKey private_key(invalid_key);
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::ValueError& e) {
            // this is the expected exception
        }

        try {
            pcrypto::sig::PrivateKey private_key(curve);
            ASSERT_FALSE(private_key);

            private_key.Deserialize(invalid_key);
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::ValueError& e) {
            // this is the expected exception
        }
    }

    // test deserialization of public key with bad values
    {
        const std::string invalid_key("this is not a serialized key");

        try {
            pcrypto::sig::PublicKey public_key(invalid_key);
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::ValueError& e) {
            // this is the expected exception
        }

        try {
            pcrypto::sig::PublicKey public_key(curve);
            ASSERT_FALSE(public_key);

            public_key.Deserialize(invalid_key);
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::ValueError& e) {
            // this is the expected exception
        }
    }

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static bool test_bignum_constructor(pcrypto::sig::SigCurve curve)
{
    // Test retrieval of the numeric key from an initialized private key
    // Then use that key to create a new private key
    {
        pcrypto::sig::PrivateKey private_key1(curve);
        private_key1.Generate();
        ASSERT_TRUE(private_key1);

        ByteArray numeric_key;
        private_key1.GetNumericKey(numeric_key);
        ASSERT_TRUE(numeric_key.size() > 0);

        pcrypto::sig::PrivateKey private_key2(curve, numeric_key);
        ASSERT_TRUE(private_key2);

        const std::string pk1_serialized = private_key1.Serialize();
        const std::string pk2_serialized = private_key2.Serialize();
        ASSERT_TRUE(pk1_serialized == pk2_serialized);
    }

    // Test numeric key constructor with an empty bytearray
    {
        try {
            ByteArray numeric_key(0,0);
            pcrypto::sig::PrivateKey private_key(curve, numeric_key);
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::CryptoError& e) {
            // this is the expected exception
            // SAFE_LOG(PDO_LOG_DEBUG, "CRYPTO ERROR: %s\n", e.what());
        }

        try {
            ByteArray numeric_key(1000,0);
            pcrypto::sig::PrivateKey private_key(curve, numeric_key);
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::CryptoError& e) {
            // this is the expected exception
            // SAFE_LOG(PDO_LOG_DEBUG, "CRYPTO ERROR: %s\n", e.what());
        }
    }

    // Test numeric key operation with uninitialized key
    {
        try {
            ByteArray numeric_key;
            pcrypto::sig::PrivateKey private_key(curve);
            private_key.GetNumericKey(numeric_key);
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::ValueError& e) {
            // this is the expected exception
            // SAFE_LOG(PDO_LOG_DEBUG, "CRYPTO ERROR: %s\n", e.what());
        }
    }

    // Test a random, but viable key; this should test that the modulo
    // arithmetic is mapping the really big number back into the space
    // where the curve is valid
    {
        ByteArray numeric_key(1000,1);
        pcrypto::sig::PrivateKey private_key(curve, numeric_key);
        ASSERT_TRUE(private_key);
    }

    {
        ByteArray numeric_key(1,1);
        pcrypto::sig::PrivateKey private_key(curve, numeric_key);
        ASSERT_TRUE(private_key);
    }

    // Test the basic numeric key functions with public keys
    {
        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();
        ASSERT_TRUE(private_key);

        pcrypto::sig::PublicKey public_key1(private_key);
        ASSERT_TRUE(public_key1);

        ByteArray numeric_key;
        public_key1.GetNumericKey(numeric_key);
        ASSERT_TRUE(numeric_key.size() > 0);

        pcrypto::sig::PublicKey public_key2(curve, numeric_key);
        ASSERT_TRUE(public_key2);

        const std::string pk1_serialized = public_key1.Serialize();
        const std::string pk2_serialized = public_key2.Serialize();
        ASSERT_TRUE(pk1_serialized == pk2_serialized);
    }

    // Test numeric key constructor with an empty bytearray
    {
        try {
            ByteArray numeric_key(0,0);
            pcrypto::sig::PublicKey public_key(curve, numeric_key);
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::CryptoError& e) {
            // this is the expected exception
            // SAFE_LOG(PDO_LOG_DEBUG, "CRYPTO ERROR: %s\n", e.what());
        }

        try {
            ByteArray numeric_key(1000,0);
            pcrypto::sig::PublicKey public_key(curve, numeric_key);
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::CryptoError& e) {
            // this is the expected exception
            // SAFE_LOG(PDO_LOG_DEBUG, "CRYPTO ERROR: %s\n", e.what());
        }
    }

    // Test numeric key operation with uninitialized key
    {
        try {
            ByteArray numeric_key;
            pcrypto::sig::PublicKey public_key(curve);
            public_key.GetNumericKey(numeric_key);
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::ValueError& e) {
            // this is the expected exception
            // SAFE_LOG(PDO_LOG_DEBUG, "CRYPTO ERROR: %s\n", e.what());
        }
    }

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static bool test_signature(pcrypto::sig::SigCurve curve)
{
    // Test signature and signature verification functions

    const std::string message_string("Proof of Elapsed Time");
    ByteArray message(message_string.begin(), message_string.end());

    const std::string message_string_alt("No proof of elapsed time");
    ByteArray message_alt(message_string_alt.begin(), message_string_alt.end());

    // Test the basic signature generation, it would be nice to verify
    // that the length of the returned signature is about right for the
    // curve in the key
    {
        ByteArray sig;

        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();

        sig = private_key.SignMessage(message);
        ASSERT_TRUE(sig.size() > 0);
    }

    // Test the signature generation with an empty message
    {
        ByteArray msg;
        ByteArray sig;

        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();

        sig = private_key.SignMessage(msg);
        ASSERT_TRUE(sig.size() > 0);
    }

    // Test signature generation with an uninitialized key, this
    // should generate a ValueError exception
    {
        ByteArray sig;

        try {
            pcrypto::sig::PrivateKey private_key(curve);
            ASSERT_FALSE(private_key);

            // this should throw an exception
            sig = private_key.SignMessage(message);
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::ValueError& e) {
            // this is the expected exception
        }
    }

    // Test basic signature verification
    {
        ByteArray sig;

        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();

        sig = private_key.SignMessage(message);
        ASSERT_TRUE(sig.size() > 0);

        pcrypto::sig::PublicKey public_key(private_key);
        int result = public_key.VerifySignature(message, sig);
        ASSERT_TRUE(result == 1);
    }

    // Test basic failed signature verification, e.g. when the
    // message does not match the signature
    {
        ByteArray sig;

        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();

        sig = private_key.SignMessage(message);
        ASSERT_TRUE(sig.size() > 0);

        pcrypto::sig::PublicKey public_key(private_key);
        int result = public_key.VerifySignature(message_alt, sig);
        ASSERT_FALSE(result == 1);
    }

    // Test basic failed signature verification, e.g. when the
    // signature is an invalid format
    {
        ByteArray sig(0,0);

        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();

        pcrypto::sig::PublicKey public_key(private_key);
        int result = public_key.VerifySignature(message, sig);
        ASSERT_FALSE(result == 1);
    }

    // Test signature verification with an uninitialized key, this
    // should generate a ValueError exception
    {
        ByteArray sig;

        try {
            pcrypto::sig::PrivateKey private_key(curve);
            private_key.Generate();

            // this should throw an exception
            sig = private_key.SignMessage(message);
            ASSERT_TRUE(sig.size() > 0);

            pcrypto::sig::PublicKey public_key(curve);
            int result = public_key.VerifySignature(message, sig);
            ASSERT_UNREACHABLE();
        }
        catch (const pdo::error::ValueError& e) {
            // this is the expected exception
        }
    }

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static bool test_assignment_operators(pcrypto::sig::SigCurve curve)
{
    // Test key assignment operator

    // basic test of assignment operator for private keys
    {
        pcrypto::sig::PrivateKey private_key1(curve);
        private_key1.Generate();

        pcrypto::sig::PrivateKey private_key2(curve);
        ASSERT_FALSE(private_key2);

        private_key2 = private_key1;
        ASSERT_TRUE(private_key2);

        const std::string serialized_key1 = private_key1.Serialize();
        const std::string serialized_key2 = private_key2.Serialize();
        ASSERT_TRUE(serialized_key1 == serialized_key2);
    }

    // basic test of assignement operator for public keys
    {
        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();

        pcrypto::sig::PublicKey public_key1(curve);
        public_key1 = private_key.GetPublicKey();
        ASSERT_TRUE(public_key1);

        pcrypto::sig::PublicKey public_key2(curve);
        ASSERT_FALSE(public_key2);

        public_key2 = public_key1;
        ASSERT_TRUE(public_key2);

        const std::string serialized_key1 = public_key1.Serialize();
        const std::string serialized_key2 = public_key2.Serialize();
        ASSERT_TRUE(serialized_key1 == serialized_key2);
    }

    // test assignment of uninitialized private key into an
    // initialized private key
    {
        pcrypto::sig::PrivateKey private_key1(curve);
        private_key1.Generate();
        ASSERT_TRUE(private_key1);

        pcrypto::sig::PrivateKey private_key2(curve);
        ASSERT_FALSE(private_key2);

        private_key1 = private_key2;
        ASSERT_FALSE(private_key1);
    }

    // test assignment of uninitialized public key into an
    // initialized public key
    {
        pcrypto::sig::PrivateKey private_key(curve);
        private_key.Generate();

        pcrypto::sig::PublicKey public_key1(curve);
        public_key1 = private_key.GetPublicKey();
        ASSERT_TRUE(public_key1);

        pcrypto::sig::PublicKey public_key2(curve);
        ASSERT_FALSE(public_key2);

        public_key1 = public_key2;
        ASSERT_FALSE(public_key1);
    }

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Utility function for testing move constructors
static pcrypto::sig::PrivateKey CreatePrivateKey(
    pcrypto::sig::SigCurve curve,
    bool initialize)
{
    pcrypto::sig::PrivateKey k(curve);
    if (initialize)
        k.Generate();
    return k;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Utility function for testing move constructors
static pcrypto::sig::PublicKey CreatePublicKey(
    pcrypto::sig::SigCurve curve,
    const pcrypto::sig::PrivateKey& private_key)
{
    pcrypto::sig::PublicKey k(private_key);
    return k;
}
