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
#include "crypto.h"
#include "error.h"
#include "types.h"

#include "scheme-private.h"

#include "SchemeExtensions.h"

#undef cons
#undef immutable_cons

// #define strvalue(p)      ((p)->_object._string._svalue)
#define strvalue(sc, p) ((sc)->vptr->string_value(p))
#define intvalue(sc, p) ((sc)->vptr->ivalue(p))

namespace pcrypto = pdo::crypto;

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

}

extern "C" void init_pcontract(scheme *sc)
{
    scheme_load_extensions(sc);
}
