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

#include <unistd.h>
#include <string>

#include "packages/base64/base64.h"
#include "packages/parson/parson.h"
#include "crypto.h"
#include "error.h"
#include "interpreter_kv.h"
#include "jsonvalue.h"
#include "log.h"
#include "pdo_error.h"
#include "types.h"

#include "scheme.h"
#include "scheme-private.h"

#include "SchemeExtensions.h"

#if _UNTRUSTED_
#include <stdio.h>
#include "packages/block_store/block_store.h"
#include "packages/block_store/lmdb_block_store.h"
#include "StateBlock.h"
#endif

#undef cons
#undef immutable_cons

// #define strvalue(p)      ((p)->_object._string._svalue)
#define strvalue(sc, p) ((sc)->vptr->string_value(p))
#define intvalue(sc, p) ((sc)->vptr->ivalue(p))

namespace pcrypto = pdo::crypto;
namespace pe = pdo::error;

const std::string pdo_error_symbol = "**pdo-error**";

/* ----------------------------------------------------------------- */
static std::string format_error_message(
    pdo::error::Error& e
    )
{
    std::string message;
    message = e.what();
    // message += e.error_code()
    return message;
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer scheme_return_error(scheme* sc, const char *message)
{
    pointer msg = sc->vptr->mk_string(sc, message);
    pointer sym =  sc->vptr->mk_symbol(sc, pdo_error_symbol.c_str());

    sc->vptr->scheme_define(sc, sc->global_env, sym, msg);

    return sym;
}

static pointer scheme_return_error_s(scheme* sc, const std::string message)
{
    return scheme_return_error(sc, message.c_str());
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static void scheme_clear_error(scheme* sc)
{
    pointer sym =  sc->vptr->mk_symbol(sc, pdo_error_symbol.c_str());
    sc->vptr->scheme_define(sc, sc->global_env, sym, sc->NIL);
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer set_closure_environment(scheme * sc, pointer args)
{
    // --------------- closure ---------------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return sc->F;

    pointer closure = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_closure(closure))
        return sc->F;

    // --------------- environment ---------------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(args))
        return sc->F;

    pointer environ = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_environment(environ))
        return sc->F;

    // --------------- last argument ---------------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return sc->F;

    sc->vptr->set_cdr(closure, environ);
    return closure;
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer copy_list(scheme * sc, pointer arg)
{
    // there is no check for looping pointers, could implement this
    // with a rational maximum depth or through a map that holds
    // previously explored pointers

    if (! sc->vptr->is_pair(arg))
        return arg;

    pointer pcar = copy_list(sc, sc->vptr->pair_car(arg));
    pointer pcdr = copy_list(sc, sc->vptr->pair_cdr(arg));

    pointer result = sc->vptr->cons(sc, pcar, pcdr);
    return result;
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer unpack_hashed_environment(scheme * sc, pointer arg)
{
    pointer result = sc->NIL;
    long vlen = sc->vptr->vector_length(arg);
    for (uint32_t elem = 0; elem < vlen; elem++)
    {
        pointer bucket = sc->vptr->vector_elem(arg, elem);
        pointer bucketlist = copy_list(sc, bucket);
        for (pointer p = bucketlist; sc->vptr->is_pair(p); p = sc->vptr->pair_cdr(p))
            result = sc->vptr->cons(sc, sc->vptr->pair_car(p), result);
    }

    return result;
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer environment_to_list(scheme * sc, pointer args)
{
    // --------------- environ ---------------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return sc->F;

    pointer environ = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_environment(environ))
        return sc->F;

    // --------------- last argument ---------------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return sc->F;

    pointer bindings = sc->vptr->pair_car(environ);

    // handle the case where the environment is represented by a hash table
    if (sc->vptr->is_vector(bindings))
        return unpack_hashed_environment(sc, bindings);

    // handle the case where the environment is represented by a list
    if (sc->vptr->is_pair(bindings))
        return copy_list(sc, bindings);

    return sc->F;
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer make_immutable(scheme * sc, pointer args)
{
    // --------------- symbol ---------------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return sc->F;

    pointer symbol = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_symbol(symbol))
        return sc->F;

    // --------------- last argument ---------------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return sc->F;

    sc->vptr->setimmutable(symbol);
    return sc->T;
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer ecdsa_create_signing_keys(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    // --------------- end of arguments ----------
    pointer rest = args;
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        pcrypto::sig::PrivateKey privkey;
        privkey.Generate();
        pcrypto::sig::PublicKey pubkey(privkey);

        std::string encpriv = privkey.Serialize();
        std::string encpub = pubkey.Serialize();

        pointer result = sc->NIL;

        pointer p_encpub = sc->vptr->mk_string(sc, encpub.c_str());
        result = sc->vptr->immutable_cons(sc, p_encpub, result);

        pointer p_encpriv = sc->vptr->mk_string(sc, encpriv.c_str());
        result = sc->vptr->immutable_cons(sc, p_encpriv, result);

        return result;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "failed to create ecdsa keys");
}

/* ----------------------------------------------------------------- */
/* (sign-message message private-key)                                */
/* ----------------------------------------------------------------- */
static pointer ecdsa_sign_message(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    pcrypto::sig::PrivateKey privkey;

    // ---------- message ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; message");

    pointer m = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(m))
        return scheme_return_error(sc, "message must be a string");

    std::string message = strvalue(sc, m);

    // ---------- private-key ----------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; private-key");

    pointer k = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(k))
        return scheme_return_error(sc, "private key must be a string");

    std::string encoded = strvalue(sc, k);

    // --------------- end of arguments ----------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        privkey.Deserialize(encoded);

        ByteArray message_array(message.begin(), message.end());
        ByteArray signature = privkey.SignMessage(message_array);
        Base64EncodedString encoded_signature = base64_encode(signature);

        pointer result = sc->vptr->mk_string(sc, encoded_signature.c_str());

        return result;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "failed to sign the message");
}

/* ----------------------------------------------------------------- */
/* (verify-signature message signature public-key)                   */
/* ----------------------------------------------------------------- */
static pointer ecdsa_verify_signature(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    pcrypto::sig::PublicKey pubkey;

    // --------------- message ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; message");

    pointer m = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(m))
        return scheme_return_error(sc, "message must be a string");

    std::string message strvalue(sc, m);

    // --------------- signature ----------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; signature");

    pointer s = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(s))
        return scheme_return_error(sc, "signature must be a string");

    Base64EncodedString encoded_signature = strvalue(sc, s);
    ByteArray signature = base64_decode(encoded_signature);

    // --------------- public-key ----------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; public-key");

    pointer k = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(k))
        return scheme_return_error(sc, "public key must be a string");

    std::string encoded = strvalue(sc, k);

    // --------------- end of arguments ----------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        ByteArray message_buf(message.begin(), message.end());

        pubkey.Deserialize(encoded);
        if (pubkey.VerifySignature(message_buf, signature))
            return sc->T;

        return sc->F;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "failed to verify the signature");
}

/* ----------------------------------------------------------------- */
/* (compute-message-hash message)                                    */
/* ----------------------------------------------------------------- */
static pointer compute_message_hash(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    // --------------- message ---------------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; message");

    pointer m = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(m))
        return scheme_return_error(sc, "message must be a string");

    std::string message = strvalue(sc, m);

    // --------------- end of argument ---------------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        ByteArray message_buf(message.begin(), message.end());
        ByteArray hash = pcrypto::ComputeMessageHash(message_buf);
        Base64EncodedString encoded_hash = base64_encode(hash);

        pointer result = sc->vptr->mk_string(sc, encoded_hash.c_str());
        return result;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "failed to compute message hash");
}

/* ----------------------------------------------------------------- */
/* (random-identifier length)                                        */
/* ----------------------------------------------------------------- */
static pointer random_identifier(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    // --------------- length ---------------
    pointer rest = args;
    if (! sc->vptr->is_pair(args))
        return scheme_return_error(sc, "missing required parameter; length");

    pointer lptr = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_integer(lptr))
        return scheme_return_error(sc, "length must be an integer");

    size_t length = (size_t)sc->vptr->ivalue(lptr);

    // --------------- end of argument ---------------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        ByteArray identifier = pcrypto::RandomBitString(length);
        Base64EncodedString encoded_identifier = base64_encode(identifier);

        pointer result = sc->vptr->mk_string(sc, encoded_identifier.c_str());
        return result;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "failed to create random identifier");
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer aes_encode_key(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    // ---------- end of argument ---------------
    pointer rest = args;
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        ByteArray aeskey = pcrypto::skenc::GenerateKey();
        Base64EncodedString encoded_aeskey = base64_encode(aeskey);

        return sc->vptr->mk_string(sc, encoded_aeskey.c_str());
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "failed to create aes keys");
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer aes_encode_iv(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    // ---------- optional: initial value ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; initial value");

    pointer k = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(k))
        return scheme_return_error(sc, "initial value must be a string");

    // --------------- end of argument ---------------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        ByteArray ivstring = pcrypto::skenc::GenerateIV(strvalue(sc, k));
        Base64EncodedString encoded_ivstring = base64_encode(ivstring);

        return sc->vptr->mk_string(sc, encoded_ivstring.c_str());
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "failed to create aes initialization vector");
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer aes_encrypt(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    pointer arg;

    // ---------- buffer ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; buffer");

    arg = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(arg))
        return scheme_return_error(sc, "buffer must be a string");

    std::string buffer = strvalue(sc, arg);

    // ---------- encoded key ----------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; aes key");

    arg = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(arg))
        return scheme_return_error(sc, "aes key must be a string");

    Base64EncodedString encoded_aeskey = strvalue(sc, arg);
    ByteArray aeskey = base64_decode(encoded_aeskey);

    // ---------- encoded IV ----------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; initialization vector");

    arg = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(arg))
        return scheme_return_error(sc, "initialization vector must be a string");

    Base64EncodedString encoded_ivstring = strvalue(sc, arg);
    ByteArray ivstring = base64_decode(encoded_ivstring);

    // encrypt!!!
    try {
        ByteArray buffer_buf(buffer.begin(), buffer.end());
        ByteArray cipher = pcrypto::skenc::EncryptMessage(aeskey, ivstring, buffer_buf);
        if (cipher.empty())
            return scheme_return_error(sc, "failed to encrypt the message");

        Base64EncodedString encoded_cipher = base64_encode(cipher);

        pointer result = sc->vptr->mk_string(sc, encoded_cipher.c_str());
        return result;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "failed to encrypt string");
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer aes_decrypt(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    pointer arg;

    // ---------- cipher text ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; cipher text");

    arg = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(arg))
        return scheme_return_error(sc, "cipher text must be a string");

    Base64EncodedString encoded_cipher = strvalue(sc, arg);
    ByteArray cipher = base64_decode(encoded_cipher);

    // ---------- encoded key ----------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; aes key");

    arg = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(arg))
        return scheme_return_error(sc, "aes key must be a string");

    Base64EncodedString encoded_aeskey = strvalue(sc, arg);
    ByteArray aeskey = base64_decode(encoded_aeskey);

    // ---------- encoded IV ----------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; iv");

    arg = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(arg))
        return scheme_return_error(sc, "iv must be a string");

    Base64EncodedString encoded_ivstring = strvalue(sc, arg);
    ByteArray ivstring = base64_decode(encoded_ivstring);

    // --------------- end of arguments ----------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    // decrypt!!!
    try {
        ByteArray buffer_buf = pcrypto::skenc::DecryptMessage(aeskey, ivstring, cipher);
        std::string buffer = ByteArrayToString(buffer_buf);

        pointer result = sc->vptr->mk_string(sc, buffer.c_str());
        return result;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "failed to decrypt cipher text");
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer rsa_create_keys(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    // --------------- end of arguments ----------
    pointer rest = args;
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        pcrypto::pkenc::PrivateKey privkey;
        privkey.Generate();
        pcrypto::pkenc::PublicKey pubkey(privkey);

        std::string encpriv = privkey.Serialize();
        std::string encpub = pubkey.Serialize();

        pointer result = sc->NIL;

        pointer p_encpub = sc->vptr->mk_string(sc, encpub.c_str());
        result = sc->vptr->immutable_cons(sc, p_encpub, result);

        pointer p_encpriv = sc->vptr->mk_string(sc, encpriv.c_str());
        result = sc->vptr->immutable_cons(sc, p_encpriv, result);

        return result;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "failed to create rsa keys");
}

/* ----------------------------------------------------------------- */
/* (encypt-message message public-key)                               */
/* ----------------------------------------------------------------- */
static pointer rsa_encrypt(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    // ---------- message ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; message");

    pointer m = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(m))
        return scheme_return_error(sc, "message must be a string");

    std::string message = strvalue(sc, m);

    // ---------- public-key ----------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; public key");

    pointer k = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(k))
        return scheme_return_error(sc, "public key must be a string");

    std::string rsa_pubkey = strvalue(sc, k);

    // --------------- last argument ---------------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        pcrypto::pkenc::PublicKey pubkey;
        pubkey.Deserialize(rsa_pubkey);

        ByteArray message_buf(message.begin(), message.end());
        ByteArray cipher = pubkey.EncryptMessage(message_buf);
        Base64EncodedString encoded_cipher = base64_encode(cipher);

        pointer result = sc->vptr->mk_string(sc, encoded_cipher.c_str());
        return result;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "failed to encrypt message");
}

/* ----------------------------------------------------------------- */
/* (rsa-decrypt-cipher cipher private-key)                               */
/* ----------------------------------------------------------------- */
static pointer rsa_decrypt(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    // ---------- message ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; cipher text");

    pointer m = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(m))
        return scheme_return_error(sc, "cipher text must be a string");

    Base64EncodedString encoded_cipher = strvalue(sc, m);
    ByteArray cipher = base64_decode(encoded_cipher);

    // ---------- private-key ----------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; rsa private key");

    pointer k = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(k))
        return scheme_return_error(sc, "private key must be a string");

    std::string rsa_privkey = strvalue(sc, k);

    // --------------- last argument ---------------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        pcrypto::pkenc::PrivateKey privkey;
        privkey.Deserialize(rsa_privkey);

        ByteArray message_buf = privkey.DecryptMessage(cipher);
        std::string message = ByteArrayToString(message_buf);

        pointer result = sc->vptr->mk_string(sc, message.c_str());
        return result;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "failed to decrypt cipher text");
}

/* ----------------------------------------------------------------- */
/* (key-value-put "key" "value")                                     */
/* ----------------------------------------------------------------- */
static pointer key_value_put(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    // pull out the key value store
    if (sc->ext_data == NULL)
        return scheme_return_error(sc, "key value store is not initialized");

    pdo::state::Interpreter_KV* keystore = (pdo::state::Interpreter_KV*)sc->ext_data;

    // --------------- key ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; key");

    pointer k = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(k))
        return scheme_return_error(sc, "key must be a string");

    // too many copies...
    std::string s_key strvalue(sc, k);
    ByteArray ba_key(s_key.begin(), s_key.end());

    // --------------- value ----------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; value");

    pointer v = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(v))
        return scheme_return_error(sc, "value must be a string");

    // too many copies
    std::string s_value strvalue(sc, v);
    ByteArray ba_value(s_value.begin(), s_value.end());

    // --------------- end of arguments ----------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        keystore->UnprivilegedPut(ba_key, ba_value);
        return sc->T;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error_s(sc, "unknown error occurred while processing key-value-put");
}

/* ----------------------------------------------------------------- */
/* (key-value-get "key") --> "value"                                 */
/* ----------------------------------------------------------------- */
static pointer key_value_get(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    // pull out the key value store
    if (sc->ext_data == NULL)
        return scheme_return_error(sc, "key value store is not initialized");

    pdo::state::Interpreter_KV* keystore = (pdo::state::Interpreter_KV*)sc->ext_data;

    // --------------- key ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; key");

    pointer k = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(k))
        return scheme_return_error(sc, "key must be a string");

    // too many copies...
    std::string s_key strvalue(sc, k);
    ByteArray ba_key(s_key.begin(), s_key.end());

    // --------------- end of arguments ----------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        ByteArray ba_value = keystore->UnprivilegedGet(ba_key);
        std::string s_value = ByteArrayToString(ba_value);
        pointer result = sc->vptr->mk_string(sc, s_value.c_str());
        return result;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error_s(sc, "unknown error occurred while processing key-value-get");
}

/* ----------------------------------------------------------------- */
/* (key-value-delete "key") --> #t/#f                                */
/* ----------------------------------------------------------------- */
static pointer key_value_delete(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    // pull out the key value store
    if (sc->ext_data == NULL)
        return scheme_return_error(sc, "key value store is not initialized");

    pdo::state::Interpreter_KV* keystore = (pdo::state::Interpreter_KV*)sc->ext_data;

    // --------------- key ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; key");

    pointer k = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(k))
        return scheme_return_error(sc, "key must be a string");

    // too many copies...
    std::string s_key strvalue(sc, k);
    ByteArray ba_key(s_key.begin(), s_key.end());

    // --------------- end of arguments ----------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        keystore->UnprivilegedDelete(ba_key);
        return sc->T;
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error_s(sc, "unknown error occurred while processing key-value-delete");
}

/* ----------------------------------------------------------------- */
/* (key-value-open "file") --> #t/#f                                 */
/* ----------------------------------------------------------------- */
#if _UNTRUSTED_
static pointer key_value_open(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    if (sc->ext_data != NULL)
        return scheme_return_error(sc, "key value store is already initialized, close first");

    // --------------- file name ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; key");

    pointer f = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(f))
        return scheme_return_error(sc, "file name must be a string");

    // too many copies...
    std::string s_filename strvalue(sc, f);

    // --------------- block id ----------
    bool use_block_id = false;
    pdo::state::StateBlockId block_id;
    if (sc->vptr->is_pair(sc->vptr->pair_cdr(rest)))
    {
        rest = sc->vptr->pair_cdr(rest);
        pointer b = sc->vptr->pair_car(rest);
        if (! sc->vptr->is_string(b))
            return scheme_return_error(sc, "block id must be a string");

        Base64EncodedString encoded_block_id = strvalue(sc, b);
        block_id = base64_decode(encoded_block_id);
        use_block_id = true;
    }

    // --------------- end of arguments ----------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    // create a key value store. we could add commands to explicitly create
    // open and close the store which would provide some nice testing
    // benefits though i think it probably excessive

    try {
        pdo::lmdb_block_store::BlockStoreOpen(s_filename);

        const ByteArray state_encryption_key(16, 0);
        pdo::state::Interpreter_KV* keystore = NULL;

        if (use_block_id)
        {
            keystore = new pdo::state::Interpreter_KV(block_id, state_encryption_key);
        }
        else
        {
            keystore = new pdo::state::Interpreter_KV(state_encryption_key);
        }

        sc->ext_data = (void*)keystore;

        return sc->T;
    }
    catch (pdo::error::ValueError& e)
    {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error_s(sc, "unknown error occurred while processing key-value-open");
}
#endif

/* ----------------------------------------------------------------- */
/* (key-value-close) --> "base64 encoded blockid"                    */
/* ----------------------------------------------------------------- */
#if _UNTRUSTED_
static pointer key_value_close(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    if (sc->ext_data == NULL)
        return scheme_return_error(sc, "key value store is not initialized");

    pdo::state::Interpreter_KV* keystore = (pdo::state::Interpreter_KV*)sc->ext_data;

    // --------------- end of arguments ----------
    pointer rest = sc->vptr->pair_cdr(args);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

    try {
        // push pending changes into the block store
        ByteArray block_id;
        keystore->Finalize(block_id);

        // close the block store
        pdo::lmdb_block_store::BlockStoreClose();

        // and clean up the interpreter storage
        sc->ext_data = NULL;
        delete keystore;

        Base64EncodedString encoded_block_id = base64_encode(block_id);
        pointer result = sc->vptr->mk_string(sc, encoded_block_id.c_str());

        return result;
    }
    catch (pdo::error::ValueError& e)
    {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error_s(sc, "unknown error occurred while processing key-value-close");
}
#endif

/* ----------------------------------------------------------------- *
 JSON Extensions -- the following functions implement conversions between
 Scheme s-expressions and JSON. Since s-expressions are more expressive
 structurally (specifically there is a difference between a vector and
 a list) there are expressions that cannot be converted to JSON. The following
 conventions are used:
    - scheme number <--> JSON number
    - scheme boolean <--> JSON boolean
    - scheme string <--> JSON string
    - scheme NIL <--> JSON Null
    - scheme vector <--> JSON array
    - scheme assoc list <--> JSON object
 Note that the last imposes several additional restrictions: keys must be
 strings, all elements of the assoc list must be exactly length 2, and the
 cadr of the element must be an expression that can be converted to JSON
 * ----------------------------------------------------------------- */

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer json_to_expression_r(scheme* sc, JSON_Value* value)
{
    JSON_Array *array = NULL;
    JSON_Object *object = NULL;
    const char* str = NULL;
    size_t i = 0;
    size_t count = 0;
    double num = 0.0;

    pointer s_pointer = NULL;

    pe::ThrowIfNull(value, "invalid json expression (null)");

    switch (json_value_get_type(value))
    {
    case JSONArray:
        array = json_value_get_array(value);
        count = json_array_get_count(array);

        s_pointer = sc->vptr->mk_vector(sc, count);

        for (i = 0; i < count; i++) {
            sc->vptr->set_vector_elem(s_pointer, i, json_to_expression_r(sc, json_array_get_value(array, i)));
        }
        return s_pointer;

    case JSONObject:
        object = json_value_get_object(value);
        count  = json_object_get_count(object);
        s_pointer = sc->NIL;

        // reverse the order to make sure that the expression is in the
        // same order as the fields in the JSON object
        for (i = count; 0 < i; i--) {
            str = json_object_get_name(object, i-1);
            pointer s_key = sc->vptr->mk_string(sc, str);
            pointer s_value = json_to_expression_r(sc, json_object_get_value(object, str));
            s_value = sc->vptr->cons(sc, s_value, sc->NIL);
            s_pointer = sc->vptr->cons(sc, sc->vptr->cons(sc, s_key, s_value), s_pointer);
        }
        return s_pointer;

    case JSONString:
        str = json_value_get_string(value);
        return (sc->vptr->mk_string(sc, str));

    case JSONBoolean:
      if (json_value_get_boolean(value))
          return sc->T;
      else
          return sc->F;

    case JSONNumber:
        num = json_value_get_number(value);
        if (num == ((double)(int)num)) /*  check if num is integer */
            return sc->vptr->mk_integer(sc, (long)num);

        return sc->vptr->mk_real(sc, num);

    case JSONNull:
        return sc->NIL;

    case JSONError:
    default:
        pe::ThrowIf<pe::RuntimeError>(true, "unknown error in JSON processing");
    }

    // should never reach here, place holder to avoid warning
    return sc->NIL;
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer json_to_expression(scheme* sc, pointer args)
{
    scheme_clear_error(sc);

    // ---------- message ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; json string");

    pointer m = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(m))
        return scheme_return_error(sc, "parameter must be a string");

    std::string message = strvalue(sc, m);

    // Parse the contract request
    try {
        JsonValue parsed(json_parse_string(message.c_str()));
        pe::ThrowIfNull(parsed.value, "failed to parse JSON expression");

        return json_to_expression_r(sc, parsed);
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "conversion from JSON failed");
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static JSON_Value *expression_to_json_r(scheme *sc, pointer expr)
{
    JSON_Value *j_value = NULL;
    JSON_Value *j_value_elem = NULL;
    JSON_Array *j_array = NULL;
    JSON_Object *j_object = NULL;
    JSON_Status jret;

    try {
        // '(("key" value) ...)
        if (sc->vptr->is_list(sc, expr))
        {
            j_value = json_value_init_object();
            j_object = json_value_get_object(j_value);

            for (pointer next = expr; next != sc->NIL; next = sc->vptr->pair_cdr(next))
            {
                pointer elem = sc->vptr->pair_car(next);
                int length = sc->vptr->list_length(sc, elem);
                pe::ThrowIf<pe::RuntimeError>(length != 2, "unable to convert s-expression to JSON, unsupported structure");

                pointer key = sc->vptr->pair_car(elem);
                pointer val = sc->vptr->pair_car(sc->vptr->pair_cdr(elem));
                pe::ThrowIf<pe::RuntimeError>(! sc->vptr->is_string(key), "invalid JSON object key representation");

                std::string key_string(strvalue(sc, key));
                j_value_elem = expression_to_json_r(sc, val);
                pe::ThrowIfNull(j_value_elem, "failed to parse element");

                jret = json_object_set_value(j_object, key_string.c_str(), j_value_elem);
                pe::ThrowIf<pe::RuntimeError>(jret != JSONSuccess, "failed to add tag to JSON object");

                j_value_elem = NULL; // need to reset this so we know when to free it correctly
            }

            return j_value;
        }
        else if (sc->vptr->is_vector(expr))
        {
            j_value = json_value_init_array();
            j_array = json_value_get_array(j_value);

            const size_t length = sc->vptr->vector_length(expr);
            for (size_t i = 0; i < length; i++)
            {
                pointer elem = sc->vptr->vector_elem(expr, i);

                j_value_elem = expression_to_json_r(sc, elem);
                pe::ThrowIfNull(j_value_elem, "failed to parse vector element");

                jret = json_array_append_value(j_array, j_value_elem);
                pe::ThrowIf<pe::RuntimeError>(jret != JSONSuccess, "failed to add element to JSON array");

                j_value_elem = NULL; // need to reset this so we know when to free it correctly
            }

            return j_value;
        }
        else if (expr == sc->NIL)
        {
            j_value = json_value_init_null();
            pe::ThrowIfNull(j_value, "failed to create JSON node");
            return j_value;
        }
        else if (expr == sc->T)
        {
            j_value = json_value_init_boolean(1);
            pe::ThrowIfNull(j_value, "failed to create JSON node");
            return j_value;
        }
        else if (expr == sc->F)
        {
            j_value = json_value_init_boolean(0);
            pe::ThrowIfNull(j_value, "failed to create JSON node");
            return j_value;
        }
        else if (sc->vptr->is_integer(expr))
        {
            j_value = json_value_init_number(sc->vptr->ivalue(expr));
            pe::ThrowIfNull(j_value, "failed to create JSON node");
            return j_value;
        }
        else if (sc->vptr->is_real(expr))
        {
            j_value = json_value_init_number(sc->vptr->rvalue(expr));
            pe::ThrowIfNull(j_value, "failed to create JSON node");
            return j_value;
        }
        else if (sc->vptr->is_string(expr))
        {
            const char* s = sc->vptr->string_value(expr);
            j_value = json_value_init_string(s);
            pe::ThrowIfNull(j_value, "failed to create JSON node");
            return j_value;
        }
        else
        {
            pe::ThrowIf<pe::RuntimeError>(true, "unknown expression type");
        }
    }
    catch (...) {
        if (j_value != NULL)
            json_value_free(j_value);

        if (j_value_elem != NULL)
            json_value_free(j_value_elem);

        throw;
    }

    // should never reach here, place holder to avoid warning
    return NULL;
}


/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer expression_to_json(scheme* sc, pointer args)
{
    if (! sc->vptr->is_pair(args))
        return sc->F;
    pointer expr = sc->vptr->pair_car(args);

    try {
        JSON_Value *j_value = expression_to_json_r(sc, expr);
        pe::ThrowIfNull(j_value, "invalid expression");

        JsonValue j_expr(j_value);

        // serialize the resulting json
        size_t serialized_size = json_serialization_size(j_expr);
        ByteArray serialized_response;
        serialized_response.resize(serialized_size);

        JSON_Status jret = json_serialize_to_buffer(
            j_expr,
            reinterpret_cast<char*>(&serialized_response[0]),
            serialized_response.size());
        pe::ThrowIf<pe::RuntimeError>(jret != JSONSuccess, "failed to serialize expression");

        std::string result = ByteArrayToString(serialized_response);
        return sc->vptr->mk_string(sc, result.c_str());
    }

    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "conversion to JSON failed");
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
static pointer validate_json(scheme* sc, pointer args)
{
    scheme_clear_error(sc);

    // ---------- message ----------
    pointer rest = args;
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; json string");

    pointer m = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(m))
        return scheme_return_error(sc, "parameter must be a string");

    std::string message = strvalue(sc, m);

    // ---------- schema ----------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; json schema");

    pointer s = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(s))
        return scheme_return_error(sc, "schema must be a string");

    std::string schema = strvalue(sc, s);

    // Parse the contract request
    try {
        JsonValue parsed_message(json_parse_string(message.c_str()));
        pe::ThrowIfNull(parsed_message.value, "failed to parse JSON expression");

        JsonValue parsed_schema(json_parse_string(schema.c_str()));
        pe::ThrowIfNull(parsed_schema.value, "failed to parse JSON schema");

        JSON_Status jret = json_validate(parsed_schema, parsed_message);
        return (jret == JSONSuccess ? sc->T : sc->F);
    }
    catch (pdo::error::Error& e) {
        return scheme_return_error_s(sc, format_error_message(e));
    }
    catch (...) {
    }

    return scheme_return_error(sc, "conversion from JSON failed");
}

/* ----------------------------------------------------------------- */
/* (enclave-log level message)                                       */
/* ----------------------------------------------------------------- */
static pointer enclave_log(scheme *sc, pointer args)
{
    scheme_clear_error(sc);

    // --------------- level ---------------
    pointer rest = args;
    if (! sc->vptr->is_pair(args))
        return scheme_return_error(sc, "missing required parameter; level");

    pointer lptr = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_integer(lptr))
        return scheme_return_error(sc, "level must be an integer");

    size_t level = (size_t)sc->vptr->ivalue(lptr);

    // --------------- message ---------------
    rest = sc->vptr->pair_cdr(rest);
    if (! sc->vptr->is_pair(rest))
        return scheme_return_error(sc, "missing required parameter; message");

    pointer m = sc->vptr->pair_car(rest);
    if (! sc->vptr->is_string(m))
        return scheme_return_error(sc, "message must be a string");

    std::string message = strvalue(sc, m);

    // --------------- end of argument ---------------
    rest = sc->vptr->pair_cdr(rest);
    if (rest != sc->NIL)
        return scheme_return_error(sc, "too many parameters");

#if UNTRUSTED
#else
    SAFE_LOG(level, "%s", message.c_str());
#endif

    return sc->T;
}

/* ----------------------------------------------------------------- */
/* ----------------------------------------------------------------- */
void scheme_load_extensions(scheme *sc)
{
    // initialize the openssl library, this really not the right
    // location; especially since this also needs to be cleaned up at
    // the end
    scheme_clear_error(sc);

    /* ---------- Add the environment functions ---------- */
    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "set-closure-environment!"),
		  sc->vptr->mk_foreign_func(sc, set_closure_environment));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "environment->list"),
		  sc->vptr->mk_foreign_func(sc, environment_to_list));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "make-immutable"),
		  sc->vptr->mk_foreign_func(sc, make_immutable));

    /* ---------- AES functions ---------- */
    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "aes-encode-key"),
		  sc->vptr->mk_foreign_func(sc, aes_encode_key));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "aes-encode-iv"),
		  sc->vptr->mk_foreign_func(sc, aes_encode_iv));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "aes-encrypt"),
		  sc->vptr->mk_foreign_func(sc, aes_encrypt));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "aes-decrypt"),
		  sc->vptr->mk_foreign_func(sc, aes_decrypt));

    /* ---------- RSA functions ---------- */
    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "rsa-create-keys"),
		  sc->vptr->mk_foreign_func(sc, rsa_create_keys));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "rsa-encrypt"),
		  sc->vptr->mk_foreign_func(sc, rsa_encrypt));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "rsa-decrypt"),
		  sc->vptr->mk_foreign_func(sc, rsa_decrypt));

    /* ---------- ECDSA functions ---------- */
    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "ecdsa-create-signing-keys"),
		  sc->vptr->mk_foreign_func(sc, ecdsa_create_signing_keys));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "ecdsa-sign-message"),
		  sc->vptr->mk_foreign_func(sc, ecdsa_sign_message));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "ecdsa-verify-signature"),
		  sc->vptr->mk_foreign_func(sc, ecdsa_verify_signature));

    /* ---------- Other extension functions ---------- */
    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "compute-message-hash"),
		  sc->vptr->mk_foreign_func(sc, compute_message_hash));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "random-identifier"),
		  sc->vptr->mk_foreign_func(sc, random_identifier));

    /* ---------- Key/Value store functions ---------- */
    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "key-value-put"),
                  sc->vptr->mk_foreign_func(sc, key_value_put));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "key-value-get"),
                  sc->vptr->mk_foreign_func(sc, key_value_get));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "key-value-delete"),
                  sc->vptr->mk_foreign_func(sc, key_value_delete));

#if _UNTRUSTED_
    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "key-value-open"),
                  sc->vptr->mk_foreign_func(sc, key_value_open));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "key-value-close"),
                  sc->vptr->mk_foreign_func(sc, key_value_close));

#endif

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "json-to-expression"),
                  sc->vptr->mk_foreign_func(sc, json_to_expression));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "expression-to-json"),
                  sc->vptr->mk_foreign_func(sc, expression_to_json));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "validate-json"),
                  sc->vptr->mk_foreign_func(sc, validate_json));

    sc->vptr->scheme_define(sc, sc->global_env,
		  sc->vptr->mk_symbol(sc, "enclave-log"),
                  sc->vptr->mk_foreign_func(sc, enclave_log));

}

extern "C" void init_pcontract(scheme *sc)
{
    scheme_load_extensions(sc);
    sc->ext_data = NULL;
}
