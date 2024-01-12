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

#include "sig_private_key.h"
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
#include "sig.h"
#include "sig_public_key.h"
#include "types.h"

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
pcrypto::sig::PrivateKey::PrivateKey(const pcrypto::sig::SigCurve& sigCurve)
{
    key_ = nullptr;
    if (sigCurve == pcrypto::sig::SigCurve::UNDEFINED)
        sigDetails_ = pcrypto::sig::SigDetails[static_cast<int>(SigCurve::PDO_DEFAULT_SIGCURVE)];
    else
        sigDetails_ = pcrypto::sig::SigDetails[static_cast<int>(sigCurve)];
}  // pcrypto::sig::PrivateKey::PrivateKey

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Custom curve constructor with initial key specified as a bignum
pcrypto::sig::PrivateKey::PrivateKey(
    const pcrypto::sig::SigCurve& sigCurve,
    const ByteArray& numeric_key) :
    pcrypto::sig::PrivateKey::PrivateKey(sigCurve)
{
    int res;

    pdo::crypto::BIGNUM_ptr bn_key(BN_bin2bn((const unsigned char*)numeric_key.data(), numeric_key.size(), NULL), BN_free);
    Error::ThrowIf<Error::MemoryError>(
        bn_key == nullptr, "Crypto Error (sig::PrivateKey): Could not create bignum");

    pdo::crypto::BN_CTX_ptr b_ctx(BN_CTX_new(), BN_CTX_free);
    Error::ThrowIf<Error::MemoryError>(
        b_ctx == nullptr, "Crypto Error (sig::PrivateKey): Cound not create BN context");

    pdo::crypto::BIGNUM_ptr r(BN_new(), BN_free);
    Error::ThrowIf<Error::MemoryError>(
        r == nullptr, "Crypto Error (sig::PrivateKey): Cound not create BN");

    pdo::crypto::BIGNUM_ptr o(BN_new(), BN_free);
    Error::ThrowIf<Error::MemoryError>(
        o == nullptr, "Crypto Error (sig::PrivateKey): Cound not create BN");

    // setup the private key
    pdo::crypto::EC_KEY_ptr private_key(EC_KEY_new(), EC_KEY_free);
    Error::ThrowIf<Error::MemoryError>(
        private_key == nullptr, "Crypto Error (sig::PrivateKey): Could not create new EC_KEY");

    pdo::crypto::EC_GROUP_ptr ec_group(EC_GROUP_new_by_curve_name(sigDetails_.sslNID), EC_GROUP_clear_free);
    Error::ThrowIf<Error::MemoryError>(
        ec_group == nullptr, "Crypto Error (sig::PrivateKey): Could not create EC_GROUP");

    res = EC_KEY_set_group(private_key.get(), ec_group.get());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PrivateKey): Could not set EC_GROUP");

    EC_GROUP_get_order(ec_group.get(), o.get(), b_ctx.get());

    res = BN_mod(r.get(), bn_key.get(), o.get(), b_ctx.get());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PrivateKey): Bignum modulus failed");

    res = EC_KEY_set_private_key(private_key.get(), r.get());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PrivateKey): Could not create new key");

    // setup the public key
    pdo::crypto::EC_POINT_ptr public_point(EC_POINT_new(ec_group.get()), EC_POINT_free);
    Error::ThrowIf<Error::MemoryError>(
        public_point == nullptr, "Crypto Error (sig::PrivateKey): Could not allocate point");

    res = EC_POINT_mul(ec_group.get(), public_point.get(), r.get(), NULL, NULL, b_ctx.get());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PrivateKey): point multiplication failed");

    res = EC_KEY_set_public_key(private_key.get(), public_point.get());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PrivateKey): failed to set public key");

    // complete the sanity check
    res = EC_KEY_check_key(private_key.get());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PrivateKey): invalid key");

    key_ = private_key.get();
    private_key.release();
}  // pcrypto::sig::PrivateKey::PrivateKey

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Constructor from encoded string
// throws RuntimeError, ValueError
pcrypto::sig::PrivateKey::PrivateKey(const std::string& encoded)
{
    key_ = nullptr;
    Deserialize(encoded);
}  // pcrypto::sig::PrivateKey::PrivateKey

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Copy constructor
// throws RuntimeError
pcrypto::sig::PrivateKey::PrivateKey(const pcrypto::sig::PrivateKey& privateKey)
{
    // when the privateKey does not have a key associated with it,
    // e.g. when privateKey.key_ == nullptr, we simply copy the
    // uninitialized state; the alternative is to throw and exception
    // with the assumption that uninitialized keys should not be assigned
    key_ = nullptr;
    if (privateKey.key_ != nullptr)
    {
        key_ = EC_KEY_dup(privateKey.key_);
        Error::ThrowIf<Error::MemoryError>(
            key_ == nullptr, "Crypto Error (sig::PrivateKey copy): Could not copy private key");
    }
    sigDetails_ = privateKey.sigDetails_;
}  // pcrypto::sig::PrivateKey::PrivateKey (copy constructor)

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Move constructor
// throws RuntimeError
pcrypto::sig::PrivateKey::PrivateKey(pcrypto::sig::PrivateKey&& privateKey)
{
    // when the privateKey does not have a key associated with it,
    // e.g. when privateKey.key_ == nullptr, we simply copy the
    // uninitialized state; the alternative is to throw and exception
    // with the assumption that uninitialized keys should not be assigned
    key_ = privateKey.key_;
    sigDetails_ = privateKey.sigDetails_;

    privateKey.key_ = nullptr;
}  // pcrypto::sig::PrivateKey::PrivateKey (move constructor)

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Destructor
pcrypto::sig::PrivateKey::~PrivateKey()
{
    ResetKey();
}  // pcrypto::sig::PrivateKey::~PrivateKey

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void pcrypto::sig::PrivateKey::ResetKey(void)
{
    // reset the the key, do not change the curve details
    if (key_)
        EC_KEY_free(key_);
    key_ = nullptr;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// boolean conversion operator, returns true if there is a
// key associated with the object
pcrypto::sig::PrivateKey::operator bool(void) const
{
    return key_ != nullptr;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// assignment operator overload
// throws RuntimeError
pcrypto::sig::PrivateKey& pcrypto::sig::PrivateKey::operator=(
    const pcrypto::sig::PrivateKey& privateKey)
{
    if (this == &privateKey)
        return *this;

    ResetKey();

    // when the privateKey does not have a key associated with it,
    // e.g. when privateKey.key_ == nullptr, we simply copy the
    // uninitialized state; the alternative is to throw and exception
    // with the assumption that uninitialized keys should not be assigned
    if (privateKey.key_ != nullptr)
    {
        key_ = EC_KEY_dup(privateKey.key_);
        Error::ThrowIf<Error::MemoryError>(
            key_ == nullptr, "Crypto Error (sig::PrivateKey::operator=): Could not copy private key");
    }
    sigDetails_ = privateKey.sigDetails_;

    return *this;
}  // pcrypto::sig::PrivateKey::operator =

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Deserialize ECDSA Private Key
// thorws RuntimeError, ValueError
void pcrypto::sig::PrivateKey::Deserialize(const std::string& encoded)
{
    ResetKey();

    pdo::crypto::BIO_ptr bio(BIO_new_mem_buf(encoded.c_str(), -1), BIO_free_all);
    Error::ThrowIf<Error::MemoryError>(
        bio == nullptr, "Crypto Error (sig::PrivateKey::Deserialize()): Could not create BIO");

    // generally we would throw a CryptoError if an OpenSSL function fails; however, in this
    // case, the conversion really means that we've been given a bad value for the key
    // so throw a value error instead
    key_ = PEM_read_bio_ECPrivateKey(bio.get(), NULL, NULL, NULL);
    Error::ThrowIf<Error::ValueError>(
        key_ == nullptr, "Crypto Error (sig::PrivateKey::Deserialize()): Could not deserialize private ECDSA key");

    SetSigDetailsFromDeserializedKey();
}  // pcrypto::sig::PrivateKey::Deserialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Generate ECDSA private key
// throws RuntimeError
void pcrypto::sig::PrivateKey::Generate()
{
    ResetKey();

    pdo::crypto::EC_KEY_ptr private_key(EC_KEY_new(), EC_KEY_free);
    Error::ThrowIf<Error::MemoryError>(
        private_key == nullptr, "Crypto Error (sig::PrivateKey::Generate): Could not create new EC_KEY");

    pdo::crypto::EC_GROUP_ptr ec_group(EC_GROUP_new_by_curve_name(sigDetails_.sslNID), EC_GROUP_clear_free);
    Error::ThrowIf<Error::MemoryError>(
        ec_group == nullptr, "Crypto Error (sig::PrivateKey::Generate): Could not create EC_GROUP");

    int res;

    res = EC_KEY_set_group(private_key.get(), ec_group.get());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PrivateKey::Generate): Could not set EC_GROUP");

    res = EC_KEY_generate_key(private_key.get());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PrivateKey::Generate): Could not generate EC_KEY");

    key_ = private_key.get();
    private_key.release();
}  // pcrypto::sig::PrivateKey::Generate

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Derive Digital Signature public key from private key
// throws RuntimeError
pcrypto::sig::PublicKey pcrypto::sig::PrivateKey::GetPublicKey() const
{
    Error::ThrowIfNull(key_, "Crypto Error (sig::PrivateKey::GetPublicKey): Private key is not initialized");

    PublicKey publicKey(*this);
    return publicKey;
}  // pcrypto::sig::GetPublicKey()

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Serialize ECDSA PrivateKey
// thorws RuntimeError
std::string pcrypto::sig::PrivateKey::Serialize() const
{
    Error::ThrowIfNull(key_, "Crypto Error (sig::PrivateKey::Serialize): Private key not initialized");

    pdo::crypto::BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free_all);
    Error::ThrowIf<Error::MemoryError>(
        bio == nullptr, "Crypto Error (sig::PrivateKey::Serialize): Could not create BIO");

    int res;

    res = PEM_write_bio_ECPrivateKey(bio.get(), key_, NULL, NULL, 0, 0, NULL);
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PrivateKey::Serialize) failed to write PEM key");

    int keylen = BIO_pending(bio.get());
    ByteArray pem_str(keylen + 1);
    res = BIO_read(bio.get(), pem_str.data(), keylen);
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PrivateKey::Serialize): Could not read BIO");

    pem_str[keylen] = '\0';
    std::string str((char*)(pem_str.data()));

    return str;
}  // pcrypto::sig::PrivateKey::Serialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Computes SHA256 hash of message.data(), signs with ECDSA privkey and
// returns ByteArray containing raw binary data
// throws RuntimeError
ByteArray pcrypto::sig::PrivateKey::SignMessage(const ByteArray& message) const
{
    Error::ThrowIfNull(key_, "Crypto Error (sig::PrivateKey::Serialize): Private key not initialized");

    // Hash, will throw exception on failure
    ByteArray hash;
    sigDetails_.SHAFunc(message, hash);

    // Then Sign
    pdo::crypto::ECDSA_SIG_ptr sig(ECDSA_do_sign(hash.data(), hash.size(), key_), ECDSA_SIG_free);
    Error::ThrowIf<Error::MemoryError>(
        sig == nullptr, "Crypto Error (SignMessage): Could not compute ECDSA signature");

    // These are pointers into the signature and do not need to be free'd after use
    const BIGNUM* rc = ECDSA_SIG_get0_r(sig.get());
    Error::ThrowIfNull(rc, "Crypto Error (SignMessage): bad r value");

    const BIGNUM* sc = ECDSA_SIG_get0_s(sig.get());
    Error::ThrowIfNull(sc, "Crypto Error (SignMessage): bad s value");

    pdo::crypto::BIGNUM_ptr s(BN_dup(sc), BN_free);
    Error::ThrowIf<Error::MemoryError>(
        s == nullptr, "Crypto Error (SignMessage): Could not dup BIGNUM for s");

    pdo::crypto::BIGNUM_ptr r(BN_dup(rc), BN_free);
    Error::ThrowIf<Error::MemoryError>(
        r == nullptr, "Crypto Error (SignMessage): Could not dup BIGNUM for r");

    pdo::crypto::BIGNUM_ptr ord(BN_new(), BN_free);
    Error::ThrowIf<Error::MemoryError>(
        ord == nullptr, "Crypto Error (SignMessage): Could not create BIGNUM for ord");

    pdo::crypto::BIGNUM_ptr ordh(BN_new(), BN_free);
    Error::ThrowIf<Error::MemoryError>(
        ordh == nullptr, "Crypto Error (SignMessage): Could not create BIGNUM for ordh");

    int res = EC_GROUP_get_order(EC_KEY_get0_group(key_), ord.get(), NULL);
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (SignMessage): Could not get order");

    res = BN_rshift(ordh.get(), ord.get(), 1);
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (SignMessage): Could not shft order BN");

    if (BN_cmp(s.get(), ordh.get()) >= 0)
    {
        res = BN_sub(s.get(), ord.get(), s.get());
        Error::ThrowIf<Error::CryptoError>(
            res <= 0, "Crypto Error (SignMessage): Could not sub BNs");
    }

    res = ECDSA_SIG_set0(sig.get(), r.get(), s.get());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (SignMessage): Could not set r and s");

    // when we invoke ECDSA_SIG_set0 control of the allocated objects is passed
    // back to the signature and released when the signature is released so we
    // need to drop control from the unique_ptr objects we've been using
    r.release();
    s.release();

    unsigned int der_sig_size = i2d_ECDSA_SIG(sig.get(), nullptr);
    ByteArray der_SIG(der_sig_size, 0);
    unsigned char* data = der_SIG.data();

    res = i2d_ECDSA_SIG(sig.get(), &data);
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (SignMessage): Could not convert signatureto DER");

    return der_SIG;
}  // pcrypto::sig::PrivateKey::SignMessage

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void pcrypto::sig::PrivateKey::GetNumericKey(ByteArray& numeric_key) const
{
    Error::ThrowIfNull(key_, "Crypto Error (sig::PrivateKey::GetNumericKey): Key not initialized");

    const BIGNUM *bn = EC_KEY_get0_private_key(key_);
    Error::ThrowIf<Error::CryptoError>(
        bn == nullptr, "Crypto Error (sig::PrivateKey::GetNumericKey) failed to retrieve the private key");

    numeric_key.resize(BN_num_bytes(bn));
    int res;

    res = BN_bn2bin(bn, numeric_key.data());
    Error::ThrowIf<Error::CryptoError>(
        res <= 0, "Crypto Error (sig::PrivateKey::GetNumericKey) failed to convert bignum");
}
