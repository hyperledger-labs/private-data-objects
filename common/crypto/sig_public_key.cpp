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

#include "sig_public_key.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <algorithm>
#include <memory>
#include <vector>
#include "base64.h"  //simple base64 enc/dec routines
#include "crypto_shared.h"
#include "error.h"
#include "hex_string.h"
#include "sig.h"
#include "hash.h"
#include "sig_private_key.h"
/***Conditional compile untrusted/trusted***/
#if _UNTRUSTED_
#include <openssl/crypto.h>
#include <stdio.h>
#else
#include "tSgxSSL_api.h"
#endif
/***END Conditional compile untrusted/trusted***/

namespace pcrypto = pdo::crypto;
namespace Error = pdo::error;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Default constructor, custom curve constructor
// PDO_DEFAULT_SIGCURVE is define that must be provided at compile time
// Its default value is set in the cmake file
pcrypto::sig::PublicKey::PublicKey(const pcrypto::sig::SigCurve& sigCurve)
{
    key_ = nullptr;
    if (sigCurve == pcrypto::sig::SigCurve::UNDEFINED)
        sigDetails_ = pcrypto::sig::SigDetails[static_cast<int>(SigCurve::PDO_DEFAULT_SIGCURVE)];
    else
        sigDetails_ = pcrypto::sig::SigDetails[static_cast<int>(sigCurve)];
} // pcrypto::sig::PublicKey::PublicKey

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Constructor from numeric key
pcrypto::sig::PublicKey::PublicKey(
    const pcrypto::sig::SigCurve& sigCurve,
    const ByteArray& numeric_key) :
    pcrypto::sig::PublicKey::PublicKey(sigCurve)
{
    int res;

    pdo::crypto::BN_CTX_ptr b_ctx(BN_CTX_new(), BN_CTX_free);
    Error::ThrowIf<Error::MemoryError>(
        b_ctx == nullptr, "Crypto Error (sig::PublicKey): Cound not create BN context");

    EC_GROUP_ptr group(EC_GROUP_new_by_curve_name(sigDetails_.sslNID), EC_GROUP_clear_free);
    Error::ThrowIf<Error::MemoryError>(
        group == nullptr, "Crypto Error (sig::PublicKey): Cound not create group");

    EC_GROUP_set_point_conversion_form(group.get(), POINT_CONVERSION_COMPRESSED);

    EC_KEY_ptr public_key(EC_KEY_new(), EC_KEY_free);
    Error::ThrowIf<Error::MemoryError>(
        public_key == nullptr, "Crypto Error (sig::PublicKey): Cound not create public_key");

    res = EC_KEY_set_group(public_key.get(), group.get());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::DeserializeXYFromHex): Could not set EC_GROUP");

    EC_POINT_ptr point(EC_POINT_new(group.get()), EC_POINT_free);
    Error::ThrowIf<Error::MemoryError>(
        point == nullptr, "Crypto Error (sig::PublicKey): Cound not create point");

    res = EC_POINT_oct2point(group.get(), point.get(), numeric_key.data(), numeric_key.size(), b_ctx.get());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PublicKey): Cound not convert octet to point");

    res = EC_KEY_set_public_key(public_key.get(), point.get());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PublicKey): Cound not set public key");

    key_ = public_key.get();
    public_key.release();
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Constructor from PrivateKey
pcrypto::sig::PublicKey::PublicKey(const pcrypto::sig::PrivateKey& privateKey)
{
    key_ = nullptr;
    sigDetails_ = privateKey.sigDetails_;

    // when the privateKey does not have a key associated with it,
    // e.g. when privateKey.key_ == nullptr, we simply copy the
    // uninitialized state; the alternative is to throw and exception
    // with the assumption that uninitialized keys should not be assigned
    if (privateKey)
    {
        int res;

        pdo::crypto::EC_KEY_ptr public_key(EC_KEY_new(), EC_KEY_free);
        Error::ThrowIf<Error::MemoryError>(
            public_key == nullptr, "Crypto Error (sig::PublicKey): Could not create new public EC_KEY");

        pdo::crypto::EC_GROUP_ptr ec_group(EC_GROUP_new_by_curve_name(sigDetails_.sslNID), EC_GROUP_clear_free);
        Error::ThrowIf<Error::MemoryError>(
            ec_group == nullptr, "Crypto Error (sig::PublicKey()): Could not create EC_GROUP");

        EC_GROUP_set_point_conversion_form(ec_group.get(), POINT_CONVERSION_COMPRESSED);

        pdo::crypto::BN_CTX_ptr context(BN_CTX_new(), BN_CTX_free);
        Error::ThrowIf<Error::MemoryError>(
            context == nullptr, "Crypto Error (sig::PublicKey): Could not create new CTX");

        res = EC_KEY_set_group(public_key.get(), ec_group.get());
        Error::ThrowIf<Error::CryptoError>(
            res <= 0, "Crypto Error (sig::PublicKey): Could not set EC_GROUP");

        const EC_POINT* p = EC_KEY_get0_public_key(privateKey.key_);
        Error::ThrowIf<Error::CryptoError>(
            p == nullptr, "Crypto Error (sig::PublicKey): Could not create new EC_POINT");

        res = EC_KEY_set_public_key(public_key.get(), p);
        Error::ThrowIf<Error::CryptoError>(
            res <= 0, "Crypto Error (sig::PublicKey): Could not set public EC_KEY");

        key_ = public_key.get();
        public_key.release();
    }

}  // pcrypto::sig::PublicKey::PublicKey

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Constructor from encoded string
// throws RuntimeError, ValueError
pcrypto::sig::PublicKey::PublicKey(const std::string& encoded)
{
    key_ = nullptr;
    Deserialize(encoded);
}  // pcrypto::sig::PublicKey::PublicKey

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Copy constructor
// throws RuntimeError
pcrypto::sig::PublicKey::PublicKey(const pcrypto::sig::PublicKey& publicKey)
{
    // when the publicKey does not have a key associated with it,
    // e.g. when publicKey.key_ == nullptr, we simply copy the
    // uninitialized state; the alternative is to throw and exception
    // with the assumption that uninitialized keys should not be assigned
    key_ = nullptr;
    if (publicKey)
    {
        key_ = EC_KEY_dup(publicKey.key_);
        Error::ThrowIf<Error::MemoryError>(
            key_ == nullptr, "Crypto Error (sig::PublicKey copy): Could not copy public key");
    }
    sigDetails_ = publicKey.sigDetails_;
}  // pcrypto::sig::PublicKey::PublicKey (copy constructor)

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Move constructor
// throws RuntimeError
pcrypto::sig::PublicKey::PublicKey(pcrypto::sig::PublicKey&& publicKey)
{
    // when the publicKey does not have a key associated with it,
    // e.g. when publicKey.key_ == nullptr, we simply copy the
    // uninitialized state; the alternative is to throw and exception
    // with the assumption that uninitialized keys should not be assigned
    key_ = publicKey.key_;
    sigDetails_ = publicKey.sigDetails_;

    publicKey.key_ = nullptr;
}  // pcrypto::sig::PublicKey::PublicKey (move constructor)

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Destructor
pcrypto::sig::PublicKey::~PublicKey()
{
    ResetKey();
}  // pcrypto::sig::PublicKey::~PublicKey

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void pcrypto::sig::PublicKey::ResetKey(void)
{
    // reset the the key, do not change the curve details
    if (key_)
        EC_KEY_free(key_);
    key_ = nullptr;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// boolean conversion operator, returns true if there is a
// key associated with the object
pcrypto::sig::PublicKey::operator bool(void) const
{
    return key_ != nullptr;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// assignment operator overload
// throws RuntimeError
pcrypto::sig::PublicKey& pcrypto::sig::PublicKey::operator=(
    const pcrypto::sig::PublicKey& publicKey)
{
    if (this == &publicKey)
        return *this;

    ResetKey();

    // when the publicKey does not have a key associated with it,
    // e.g. when publicKey.key_ == nullptr, we simply copy the
    // uninitialized state; the alternative is to throw and exception
    // with the assumption that uninitialized keys should not be assigned
    if (publicKey.key_ != nullptr)
    {
        key_ = EC_KEY_dup(publicKey.key_);
        Error::ThrowIf<Error::MemoryError>(
            key_ == nullptr, "Crypto Error (sig::PublicKey::operator=): Could not copy public key");
    }
    sigDetails_ = publicKey.sigDetails_;

    return *this;
}  // pcrypto::sig::PublicKey::operator =

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Deserialize Digital Signature Public Key
// throws RunTime
void pcrypto::sig::PublicKey::Deserialize(const std::string& encoded)
{
    ResetKey();

    pdo::crypto::BIO_ptr bio(BIO_new_mem_buf(encoded.c_str(), -1), BIO_free_all);
    Error::ThrowIf<Error::MemoryError>(
        bio == nullptr, "Crypto Error (sig::Deserialize()): Could not create BIO");

    // generally we would throw a CryptoError if an OpenSSL function fails; however, in this
    // case, the conversion really means that we've been given a bad value for the key
    // so throw a value error instead
    key_ = PEM_read_bio_EC_PUBKEY(bio.get(), NULL, NULL, NULL);
    Error::ThrowIf<Error::ValueError>(
        key_ == nullptr, "Crypto Error (sig::Deserialize()): Could not deserialize public ECDSA key");

    SetSigDetailsFromDeserializedKey();
}  // pcrypto::sig::PublicKey::Deserialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Serialize Digital Signature Public Key
// throws RuntimeError
std::string pcrypto::sig::PublicKey::Serialize() const
{
    Error::ThrowIfNull(key_, "Crypto Error (sig::PublicKey::Serialize): public key not initialized");

    pdo::crypto::BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free_all);
    Error::ThrowIf<Error::MemoryError>(
        bio == nullptr, "Crypto Error (Serialize): Could not create BIO");

    int res;

    res = PEM_write_bio_EC_PUBKEY(bio.get(), key_);
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PublicKey::Serialize): Could not serialize key");

    int keylen = BIO_pending(bio.get());

    ByteArray pem_str(keylen + 1);

    res = BIO_read(bio.get(), pem_str.data(), keylen);
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PublicKey::Serialize): Could not read BIO");

    pem_str[keylen] = '\0';
    std::string str(reinterpret_cast<char*>(pem_str.data()));

    return str;
}  // pcrypto::sig::PublicKey::Serialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Verifies SHA256 ECDSA signature of message
// input signature ByteArray contains raw binary data
// returns 1 if signature is valid, 0 if signature is invalid and -1 if there is
// an internal error
int pcrypto::sig::PublicKey::VerifySignature(
    const ByteArray& message, const ByteArray& signature) const
{
    Error::ThrowIfNull(key_, "Crypto Error (sig::PublicKey::VerifySignature): public key not initialized");

    ByteArray hash;
    sigDetails_.SHAFunc(message, hash);

    // Decode signature B64 -> DER -> ECDSA_SIG
    const unsigned char* der_SIG = (const unsigned char*)signature.data();
    pdo::crypto::ECDSA_SIG_ptr sig(
        d2i_ECDSA_SIG(NULL, (const unsigned char**)(&der_SIG), signature.size()), ECDSA_SIG_free);
    if (! sig)
        return -1;

    // Verify
    return ECDSA_do_verify(hash.data(), hash.size(), sig.get(), key_);
}  // pcrypto::sig::PublicKey::VerifySignature

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void pcrypto::sig::PublicKey::GetNumericKey(ByteArray& numeric_key) const
{
    Error::ThrowIfNull(key_, "Crypto Error (sig::PublicKey::GetNumericKey): Key not initialized");

    pdo::crypto::BN_CTX_ptr b_ctx(BN_CTX_new(), BN_CTX_free);
    Error::ThrowIf<Error::MemoryError>(
        b_ctx == nullptr, "Crypto Error (sig::PublicKey): Cound not create BN context");

    const EC_GROUP *group = EC_KEY_get0_group(key_);
    const EC_POINT *point = EC_KEY_get0_public_key(key_);

    int result;

    // this call just returns the size of the buffer that is necessary
    result = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, NULL, 0, b_ctx.get());
    numeric_key.resize(result);

    // this call writes the data to the numeric_key
    result = EC_POINT_point2oct(
        group, point, POINT_CONVERSION_COMPRESSED, numeric_key.data(), numeric_key.size(), b_ctx.get());
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
unsigned int pcrypto::sig::PublicKey::MaxSigSize(const std::string& encoded)
{
    pcrypto::sig::PublicKey pu(encoded);
    return pu.Key::MaxSigSize();
}
