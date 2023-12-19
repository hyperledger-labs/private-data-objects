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

// Error handling
namespace Error = pdo::error;

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Utility function: Deserialize ECDSA Private Key
// throws RuntimeError, ValueError
EC_KEY* deserializeECDSAPrivateKey(const std::string& encoded)
{
    BIO_ptr bio(BIO_new_mem_buf(encoded.c_str(), -1), BIO_free_all);
    if (!bio)
    {
        std::string msg("Crypto Error (deserializeECDSAPrivateKey): Could not create BIO");
        throw Error::RuntimeError(msg);
    }

    EC_KEY* private_key = PEM_read_bio_ECPrivateKey(bio.get(), NULL, NULL, NULL);
    if (!private_key)
    {
        std::string msg(
            "Crypto Error (deserializeECDSAPrivateKey): Could not "
            "deserialize private ECDSA key");
        throw Error::ValueError(msg);
    }
    return private_key;
}  // deserializeECDSAPrivateKey

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Default constructor (default curve specified in PDO_DEFAULT_SIGCURVE)
// PDO_DEFAULT_SIGCURVE is define that must be provided at compile time
// Its default value is set in the cmake file
 pcrypto::sig::PrivateKey::PrivateKey() :
    pcrypto::sig::PrivateKey::PrivateKey(SigCurve::PDO_DEFAULT_SIGCURVE)
{}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Custom curve constructor
pcrypto::sig::PrivateKey::PrivateKey(const pcrypto::sig::SigCurve& sigCurve)
{
    sigDetails_ = pcrypto::sig::SigDetails[static_cast<int>(sigCurve)];
    key_ = nullptr;
}  // pcrypto::sig::PrivateKey::PrivateKey

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Custom curve constructor
pcrypto::sig::PrivateKey::PrivateKey(
    const pcrypto::sig::SigCurve& sigCurve,
    const BIGNUM* numeric_key) :
    pcrypto::sig::PrivateKey::PrivateKey(sigCurve)
{
    pdo::crypto::BN_CTX_ptr b_ctx(BN_CTX_new(), BN_CTX_free);
    pdo::error::ThrowIfNull(b_ctx.get(), "Crypto Error (sig::PrivateKey()): Cound not create BN context");

    pdo::crypto::BIGNUM_ptr r(BN_new(), BN_free);
    pdo::error::ThrowIfNull(r.get(), "Crypto Error (sig::PrivateKey()): Cound not create BN");

    pdo::crypto::BIGNUM_ptr o(BN_new(), BN_free);
    pdo::error::ThrowIfNull(o.get(), "Crypto Error (sig::PrivateKey()): Cound not create BN");

    // setup the private key
    pdo::crypto::EC_KEY_ptr private_key(EC_KEY_new(), EC_KEY_free);
    pdo::error::ThrowIfNull(private_key.get(), "Crypto Error (sig::PrivateKey()): Could not create new EC_KEY");

    pdo::crypto::EC_GROUP_ptr ec_group(EC_GROUP_new_by_curve_name(sigDetails_.sslNID), EC_GROUP_clear_free);
    pdo::error::ThrowIfNull(ec_group.get(), "Crypto Error (sig::PrivateKey()): Could not create EC_GROUP");

    pdo::error::ThrowIf<Error::RuntimeError>(
        ! EC_KEY_set_group(private_key.get(), ec_group.get()),
        "Crypto Error (sig::PrivateKey()): Could not set EC_GROUP");

    EC_GROUP_get_order(ec_group.get(), o.get(), b_ctx.get());
    pdo::error::ThrowIf<Error::RuntimeError>(
        ! BN_mod(r.get(), numeric_key, o.get(), b_ctx.get()),
        "Crypto Error (sig::PrivateKey()): Bignum modulus failed");

    pdo::error::ThrowIf<Error::RuntimeError>(
        ! EC_KEY_set_private_key(private_key.get(), r.get()),
        "Crypto Error (sig::PrivateKey()): Could not create new key");

    // setup the public key
    pdo::crypto::EC_POINT_ptr public_point(EC_POINT_new(ec_group.get()), EC_POINT_free);
    pdo::error::ThrowIfNull(public_point.get(), "Crypto Error (sig::PrivateKey()): Could not allocate point");

    pdo::error::ThrowIf<Error::RuntimeError>(
        ! EC_POINT_mul(ec_group.get(), public_point.get(), r.get(), NULL, NULL, b_ctx.get()),
        "Crypto Error (sig::PrivateKey()): point multiplication failed");

    pdo::error::ThrowIf<Error::RuntimeError>(
        ! EC_KEY_set_public_key(private_key.get(), public_point.get()),
        "Crypto Error (sig::PrivateKey()): failed to set public key");

    // complete the sanity check
    pdo::error::ThrowIf<Error::RuntimeError>(
        ! EC_KEY_check_key(private_key.get()),
        "Crypto Error (sig::PrivateKey()): something is wrong with the key");

    key_ = EC_KEY_dup(private_key.get());
    pdo::error::ThrowIf<Error::RuntimeError>(! key_, "Crypto Error (sig::PrivateKey()): Could not dup private EC_KEY");
}  // pcrypto::sig::PrivateKey::PrivateKey

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Constructor from encoded string
// throws RuntimeError, ValueError
pcrypto::sig::PrivateKey::PrivateKey(const std::string& encoded)
{
    key_ = deserializeECDSAPrivateKey(encoded);
    SetSigDetailsFromDeserializedKey();
}  // pcrypto::sig::PrivateKey::PrivateKey

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Copy constructor
// throws RuntimeError
pcrypto::sig::PrivateKey::PrivateKey(const pcrypto::sig::PrivateKey& privateKey)
{
    ResetKey();

    sigDetails_ = privateKey.sigDetails_;
    key_ = EC_KEY_dup(privateKey.key_);
    if (!key_)
    {
        std::string msg("Crypto Error (sig::PrivateKey() copy): Could not copy private key");
        throw Error::RuntimeError(msg);
    }
}  // pcrypto::sig::PrivateKey::PrivateKey (copy constructor)

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Move constructor
// throws RuntimeError
pcrypto::sig::PrivateKey::PrivateKey(pcrypto::sig::PrivateKey&& privateKey)
{
    ResetKey();

    sigDetails_ = privateKey.sigDetails_;
    key_ = privateKey.key_;
    privateKey.key_ = nullptr;
    if (!key_)
    {
        std::string msg("Crypto Error (sig::PrivateKey() move): Cannot move null private key");
        throw Error::RuntimeError(msg);
    }
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
// assignment operator overload
// throws RuntimeError
pcrypto::sig::PrivateKey& pcrypto::sig::PrivateKey::operator=(
    const pcrypto::sig::PrivateKey& privateKey)
{
    if (this == &privateKey)
        return *this;

    ResetKey();

    sigDetails_ = privateKey.sigDetails_;
    key_ = EC_KEY_dup(privateKey.key_);
    if (!key_)
    {
        std::string msg("Crypto Error (sig::PrivateKey operator =): Could not copy private key");
        throw Error::RuntimeError(msg);
    }

    return *this;
}  // pcrypto::sig::PrivateKey::operator =

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Deserialize ECDSA Private Key
// thorws RuntimeError, ValueError
void pcrypto::sig::PrivateKey::Deserialize(const std::string& encoded)
{
    ResetKey();

    pdo::crypto::BIO_ptr bio(BIO_new_mem_buf(encoded.c_str(), -1), BIO_free_all);
    pdo::error::ThrowIfNull(bio.get(), "Crypto Error (sig::Deserialize()): Could not create BIO");

    key_ = PEM_read_bio_ECPrivateKey(bio.get(), NULL, NULL, NULL);
    pdo::error::ThrowIfNull(key_, "Crypto Error (sig::Deserialize()): Could not deserialize private ECDSA key");

    SetSigDetailsFromDeserializedKey();
}  // pcrypto::sig::PrivateKey::Deserialize

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Generate ECDSA private key
// throws RuntimeError
void pcrypto::sig::PrivateKey::Generate()
{
    ResetKey();

    pdo::crypto::EC_KEY_ptr private_key(EC_KEY_new(), EC_KEY_free);

    if (!private_key)
    {
        std::string msg("Crypto Error (sig::PrivateKey()): Could not create new EC_KEY");
        throw Error::RuntimeError(msg);
    }

    pdo::crypto::EC_GROUP_ptr ec_group(EC_GROUP_new_by_curve_name(sigDetails_.sslNID), EC_GROUP_clear_free);
    if (!ec_group)
    {
        std::string msg("Crypto Error (sig::PrivateKey()): Could not create EC_GROUP");
        throw Error::RuntimeError(msg);
    }

    if (!EC_KEY_set_group(private_key.get(), ec_group.get()))
    {
        std::string msg("Crypto Error (sig::PrivateKey()): Could not set EC_GROUP");
        throw Error::RuntimeError(msg);
    }

    if (!EC_KEY_generate_key(private_key.get()))
    {
        std::string msg("Crypto Error (sig::PrivateKey()): Could not generate EC_KEY");
        throw Error::RuntimeError(msg);
    }

    key_ = EC_KEY_dup(private_key.get());
    if (!key_)
    {
        std::string msg("Crypto Error (sig::PrivateKey()): Could not dup private EC_KEY");
        throw Error::RuntimeError(msg);
    }
}  // pcrypto::sig::PrivateKey::Generate

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Derive Digital Signature public key from private key
// throws RuntimeError
pcrypto::sig::PublicKey pcrypto::sig::PrivateKey::GetPublicKey() const
{
    PublicKey publicKey(*this);
    return publicKey;
}  // pcrypto::sig::GetPublicKey()

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Serialize ECDSA PrivateKey
// thorws RuntimeError
std::string pcrypto::sig::PrivateKey::Serialize() const
{
    pdo::crypto::BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free_all);

    if (!bio)
    {
        std::string msg("Crypto Error (Serialize): Could not create BIO");
        throw Error::RuntimeError(msg);
    }

    PEM_write_bio_ECPrivateKey(bio.get(), key_, NULL, NULL, 0, 0, NULL);

    int keylen = BIO_pending(bio.get());

    ByteArray pem_str(keylen + 1);
    if (!BIO_read(bio.get(), pem_str.data(), keylen))
    {
        std::string msg("Crypto Error (Serialize): Could not read BIO");
        throw Error::RuntimeError(msg);
    }
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
    //unsigned char hash[sigDetails_.shaDigestLength];
    ByteArray hash;

    // Hash
    sigDetails_.SHAFunc(message, hash);
    // Then Sign

    pdo::crypto::ECDSA_SIG_ptr sig(ECDSA_do_sign(hash.data(), hash.size(), key_), ECDSA_SIG_free);
    pdo::error::ThrowIf<Error::RuntimeError>(!sig, "Crypto Error (SignMessage): Could not compute ECDSA signature");

    const BIGNUM* sc;
    const BIGNUM* rc;
    BIGNUM* r = nullptr;
    BIGNUM* s = nullptr;

    ECDSA_SIG_get0(sig.get(), &rc, &sc);

    s = BN_dup(sc);
    pdo::error::ThrowIf<Error::RuntimeError>(!s, "Crypto Error (SignMessage): Could not dup BIGNUM for s");

    r = BN_dup(rc);
    pdo::error::ThrowIf<Error::RuntimeError>(!r, "Crypto Error (SignMessage): Could not dup BIGNUM for r");

    pdo::crypto::BIGNUM_ptr ord(BN_new(), BN_free);
    pdo::error::ThrowIf<Error::RuntimeError>(!ord,"Crypto Error (SignMessage): Could not create BIGNUM for ord");

    pdo::crypto::BIGNUM_ptr ordh(BN_new(), BN_free);
    pdo::error::ThrowIf<Error::RuntimeError>(!ordh, "Crypto Error (SignMessage): Could not create BIGNUM for ordh");

    int res = EC_GROUP_get_order(EC_KEY_get0_group(key_), ord.get(), NULL);
    pdo::error::ThrowIf<Error::RuntimeError>(!res, "Crypto Error (SignMessage): Could not get order");

    res = BN_rshift(ordh.get(), ord.get(), 1);
    pdo::error::ThrowIf<Error::RuntimeError>(!res, "Crypto Error (SignMessage): Could not shft order BN");

    if (BN_cmp(s, ordh.get()) >= 0)
    {
        res = BN_sub(s, ord.get(), s);
        pdo::error::ThrowIf<Error::RuntimeError>(!res, "Crypto Error (SignMessage): Could not sub BNs");
    }

    res = ECDSA_SIG_set0(sig.get(), r, s);
    pdo::error::ThrowIf<Error::RuntimeError>(!res, "Crypto Error (SignMessage): Could not set r and s");

    // The -1 here is because we canonoicalize the signature as in Bitcoin
    unsigned int der_sig_size = i2d_ECDSA_SIG(sig.get(), nullptr);
    ByteArray der_SIG(der_sig_size, 0);
    unsigned char* data = der_SIG.data();

    res = i2d_ECDSA_SIG(sig.get(), &data);
    pdo::error::ThrowIf<Error::RuntimeError>(!res, "Crypto Error (SignMessage): Could not convert signatureto DER");

    return der_SIG;
}  // pcrypto::sig::PrivateKey::SignMessage
