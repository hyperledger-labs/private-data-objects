/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <string>

#include "bh_platform.h"
#include "wasm_export.h"
#include "lib_export.h"

#include "packages/parson/parson.h"

#include "crypto.h"
#include "error.h"
#include "jsonvalue.h"
#include "log.h"
#include "pdo_error.h"
#include "types.h"

#include <string.h>
#include <ctype.h>
#include <math.h>

#include "WasmCryptoExtensions.h"
#include "WasmUtil.h"

namespace pe = pdo::error;
namespace pcrypto = pdo::crypto;

/* ----------------------------------------------------------------- *
 * NAME: _b64_encode_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool b64_encode_wrapper(
    wasm_exec_env_t exec_env,
    const int32 dec_buffer_offset, // uint8_t*
    const int32 dec_buffer_length, // size_t
    int32 enc_buffer_pointer_offset, // char**
    int32 enc_length_pointer_offset  // size_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t* dec_buffer = (uint8_t*)get_buffer(module_inst, dec_buffer_offset, dec_buffer_length);
        if (dec_buffer == NULL)
            return false;

        ByteArray src(dec_buffer, dec_buffer + dec_buffer_length);
        Base64EncodedString encoded = ByteArrayToBase64EncodedString(src);

        if (! save_buffer(module_inst, encoded, enc_buffer_pointer_offset, enc_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: _b64_decode_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool b64_decode_wrapper(
    wasm_exec_env_t exec_env,
    const int32 enc_buffer_offset, // char*
    const int32 enc_buffer_length, // size_t
    int32 dec_buffer_pointer_offset, // uint8_t**
    int32 dec_length_pointer_offset  // size_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t* enc_buffer = (uint8_t*)get_buffer(module_inst, enc_buffer_offset, enc_buffer_length);
        if (enc_buffer == NULL)
            return false;

        Base64EncodedString encoded(enc_buffer, enc_buffer + enc_buffer_length);
        ByteArray decoded = Base64EncodedStringToByteArray(encoded);
        if (decoded.size() == 0)
            return false;

        if (! save_buffer(module_inst, decoded, dec_buffer_pointer_offset, dec_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: _ecdsa_create_signing_keys
 * ----------------------------------------------------------------- */
extern "C" bool ecdsa_create_signing_keys_wrapper(
    wasm_exec_env_t exec_env,
    int32 private_buffer_pointer_offset, // char**
    int32 private_length_pointer_offset, // size_t*
    int32 public_buffer_pointer_offset,  // char**
    int32 public_length_pointer_offset   // size_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        pcrypto::sig::PrivateKey privkey;
        privkey.Generate();
        pcrypto::sig::PublicKey pubkey(privkey);

        std::string encpriv = privkey.Serialize();
        std::string encpub = pubkey.Serialize();

        if (! save_buffer(module_inst, encpriv, private_buffer_pointer_offset, private_length_pointer_offset))
            return false;

        if (! save_buffer(module_inst, encpub, public_buffer_pointer_offset, public_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: _ecdsa_sign_message_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool ecdsa_sign_message_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset, // uint8_t*
    const int32 msg_length,        // size_t
    const int32 key_buffer_offset, // char*
    const int32 key_length,        // size_t
    int32 sig_buffer_pointer_offset, // uint8_t**
    int32 sig_length_pointer_offset  // size_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        const uint8_t* msg_buffer = (uint8_t*)get_buffer(module_inst, msg_buffer_offset, msg_length);
        if (msg_buffer == NULL)
            return false;

        const char* key_buffer = (const char*)get_buffer(module_inst, key_buffer_offset, key_length);
        if (key_buffer == NULL)
            return false;

        ByteArray msg(msg_buffer, msg_buffer + msg_length);
        std::string key(key_buffer, key_length);

        pcrypto::sig::PrivateKey privkey(key);
        ByteArray signature = privkey.SignMessage(msg);

        if (! save_buffer(module_inst, signature, sig_buffer_pointer_offset, sig_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: _ecdsa_verify_signature_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool ecdsa_verify_signature_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset, // uint8_t*
    const int32 msg_length,        // size_t
    const int32 key_buffer_offset, // char*
    const int32 key_length,        // size_t
    const int32 sig_buffer_offset, // uint8_t*
    const int32 sig_length         // size_t
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        const uint8_t* msg_buffer = (uint8_t*)get_buffer(module_inst, msg_buffer_offset, msg_length);
        if (msg_buffer == NULL)
            return false;

        const char* key_buffer = (const char*)get_buffer(module_inst, key_buffer_offset, key_length);
        if (key_buffer == NULL)
            return false;

        const uint8_t* sig_buffer = (uint8_t*)get_buffer(module_inst, sig_buffer_offset, sig_length);
        if (key_buffer == NULL)
            return false;

        ByteArray msg(msg_buffer, msg_buffer + msg_length);
        std::string key(key_buffer, key_length);
        ByteArray signature(sig_buffer, sig_buffer + sig_length);

        pcrypto::sig::PublicKey pubkey(key);
        return pubkey.VerifySignature(msg, signature);
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: aes_generate_key_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool aes_generate_key_wrapper(
    wasm_exec_env_t exec_env,
    int32 key_buffer_pointer_offset, // uint8_t**
    int32 key_length_pointer_offset  // size_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        ByteArray key = pcrypto::skenc::GenerateKey();

        if (! save_buffer(module_inst, key, key_buffer_pointer_offset, key_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: aes_generate_iv_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool aes_generate_iv_wrapper(
    wasm_exec_env_t exec_env,
    const int32 buffer_offset,  // uint8_t*
    const int32 buffer_length,  // size_t
    int32 iv_buffer_pointer_offset, // uint8_t**
    int32 iv_length_pointer_offset  // size_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        const uint8_t* buffer = (uint8_t*)get_buffer(module_inst, buffer_offset, buffer_length);
        if (buffer == NULL)
            return false;

        ByteArray iv = pcrypto::skenc::GenerateIV((const char*)buffer);

        if (! save_buffer(module_inst, iv, iv_buffer_pointer_offset, iv_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: aes_encrypt_message_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool aes_encrypt_message_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset, // uint8_t*
    const int32 msg_length,        // size_t
    const int32 key_buffer_offset, // uint8_t*
    const int32 key_length,        // size_t
    const int32 iv_buffer_offset,  // uint8_t*
    const int32 iv_length,         // size_t
    int32 cipher_buffer_pointer_offset, // uint8_t**
    int32 cipher_length_pointer_offset  // size_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t* msg_buffer = (uint8_t*)get_buffer(module_inst, msg_buffer_offset, msg_length);
        if (msg_buffer == NULL)
            return false;
        ByteArray msg(msg_buffer, msg_buffer + msg_length);

        uint8_t* key_buffer = (uint8_t*)get_buffer(module_inst, key_buffer_offset, key_length);
        if (key_buffer == NULL)
            return false;
        ByteArray key(key_buffer, key_buffer + key_length);

        uint8_t* iv_buffer = (uint8_t*)get_buffer(module_inst, iv_buffer_offset, iv_length);
        if (iv_buffer == NULL)
            return false;
        ByteArray iv(iv_buffer, iv_buffer + iv_length);

        ByteArray cipher = pcrypto::skenc::EncryptMessage(key, iv, msg);
        if (cipher.empty())
            return false;

        if (! save_buffer(module_inst, cipher, cipher_buffer_pointer_offset, cipher_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: aes_decrypt_message_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool aes_decrypt_message_wrapper(
    wasm_exec_env_t exec_env,
    const int32 cipher_buffer_offset, // uint8_t*
    const int32 cipher_length,        // size_t
    const int32 key_buffer_offset,    // uint8_t*
    const int32 key_length,           // size_t
    const int32 iv_buffer_offset,     // uint8_t*
    const int32 iv_length,            // size_t
    int32 msg_buffer_pointer_offset,  // uint8_t**
    int32 msg_length_pointer_offset   // size_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t* cipher_buffer = (uint8_t*)get_buffer(module_inst, cipher_buffer_offset, cipher_length);
        if (cipher_buffer == NULL)
            return false;
        ByteArray cipher(cipher_buffer, cipher_buffer + cipher_length);

        uint8_t* key_buffer = (uint8_t*)get_buffer(module_inst, key_buffer_offset, key_length);
        if (key_buffer == NULL)
            return false;
        ByteArray key(key_buffer, key_buffer + key_length);

        uint8_t* iv_buffer = (uint8_t*)get_buffer(module_inst, iv_buffer_offset, iv_length);
        if (iv_buffer == NULL)
            return false;
        ByteArray iv(iv_buffer, iv_buffer + iv_length);

        ByteArray msg = pcrypto::skenc::DecryptMessage(key, iv, cipher);
        if (msg.empty())
            return false;

        if (! save_buffer(module_inst, msg, msg_buffer_pointer_offset, msg_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: rsa_generate_keys_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool rsa_generate_keys_wrapper(
    wasm_exec_env_t exec_env,
    int32 private_buffer_pointer_offset, // char**
    int32 private_length_pointer_offset, // size_t*
    int32 public_buffer_pointer_offset,  // char**
    int32 public_length_pointer_offset   // size_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        pcrypto::pkenc::PrivateKey privkey;
        privkey.Generate();
        pcrypto::pkenc::PublicKey pubkey(privkey);

        std::string encpriv = privkey.Serialize();
        std::string encpub = pubkey.Serialize();

        if (! save_buffer(module_inst, encpriv, private_buffer_pointer_offset, private_length_pointer_offset))
            return false;

        if (! save_buffer(module_inst, encpub, public_buffer_pointer_offset, public_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: rsa_encrypt_message_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool rsa_encrypt_message_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset, // uint8_t*
    const int32 msg_length,        // size_t
    const int32 key_buffer_offset, // char*
    const int32 key_length,        // size_t
    int32 cipher_buffer_pointer_offset, // uint8_t**
    int32 cipher_length_pointer_offset  // size_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t* msg_buffer = (uint8_t*)get_buffer(module_inst, msg_buffer_offset, msg_length);
        if (msg_buffer == NULL)
            return false;
        ByteArray msg(msg_buffer, msg_buffer + msg_length);

        char* key_buffer = (char*)get_buffer(module_inst, key_buffer_offset, key_length);
        if (key_buffer == NULL)
            return false;
        std::string key(key_buffer, key_length);

        pcrypto::pkenc::PublicKey public_key;
        public_key.Deserialize(key);

        ByteArray cipher = public_key.EncryptMessage(msg);
        if (cipher.empty())
            return false;

        if (! save_buffer(module_inst, cipher, cipher_buffer_pointer_offset, cipher_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: rsa_decrypt_message_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool rsa_decrypt_message_wrapper(
    wasm_exec_env_t exec_env,
    const int32 cipher_buffer_offset, // uint8_t*
    const int32 cipher_length,        // size_t
    const int32 key_buffer_offset,    // char*
    const int32 key_length,           // size_t
    int32 msg_buffer_pointer_offset,  // uint8_t**
    int32 msg_length_pointer_offset   // size_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t* cipher_buffer = (uint8_t*)get_buffer(module_inst, cipher_buffer_offset, cipher_length);
        if (cipher_buffer == NULL)
            return false;
        ByteArray cipher(cipher_buffer, cipher_buffer + cipher_length);

        char* key_buffer = (char*)get_buffer(module_inst, key_buffer_offset, key_length);
        if (key_buffer == NULL)
            return false;
        std::string key(key_buffer, key_length);

        pcrypto::pkenc::PrivateKey private_key;
        private_key.Deserialize(key);

        ByteArray msg = private_key.DecryptMessage(cipher);
        if (msg.empty())
            return false;

        if (! save_buffer(module_inst, msg, msg_buffer_pointer_offset, msg_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: sha256_hash_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool sha256_hash_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset, // uint8_t*
    const int32 msg_buffer_length, // size_t
    int32 hash_buffer_pointer_offset, // uint8_t**
    int32 hash_length_pointer_offset) // size_t*
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t* msg_buffer = (uint8_t*)get_buffer(module_inst, msg_buffer_offset, msg_buffer_length);
        if (msg_buffer == NULL)
            return false;

        ByteArray msg(msg_buffer, msg_buffer + msg_buffer_length);
        ByteArray hash;
        pcrypto::SHA256Hash(msg, hash);
        if (hash.size() == 0)
            return false;

        if (! save_buffer(module_inst, hash, hash_buffer_pointer_offset, hash_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: sha384_hash_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool sha384_hash_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset, // uint8_t*
    const int32 msg_buffer_length, // size_t
    int32 hash_buffer_pointer_offset, // uint8_t**
    int32 hash_length_pointer_offset) // size_t*
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t* msg_buffer = (uint8_t*)get_buffer(module_inst, msg_buffer_offset, msg_buffer_length);
        if (msg_buffer == NULL)
            return false;

        ByteArray msg(msg_buffer, msg_buffer + msg_buffer_length);
        ByteArray hash;
        pcrypto::SHA384Hash(msg, hash);
        if (hash.size() == 0)
            return false;

        if (! save_buffer(module_inst, hash, hash_buffer_pointer_offset, hash_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: sha512_hash_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool sha512_hash_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset, // uint8_t*
    const int32 msg_buffer_length, // size_t
    int32 hash_buffer_pointer_offset, // uint8_t**
    int32 hash_length_pointer_offset) // size_t*
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t* msg_buffer = (uint8_t*)get_buffer(module_inst, msg_buffer_offset, msg_buffer_length);
        if (msg_buffer == NULL)
            return false;

        ByteArray msg(msg_buffer, msg_buffer + msg_buffer_length);
        ByteArray hash;
        pcrypto::SHA512Hash(msg, hash);
        if (hash.size() == 0)
            return false;

        if (! save_buffer(module_inst, hash, hash_buffer_pointer_offset, hash_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: _random_identifier_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool random_identifier_wrapper(
    wasm_exec_env_t exec_env,
    const int32 length,         // size_t
    int32 buffer_offset         // uint8_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    if (length <= 0)
        return false;

    try {
        ByteArray identifier = pcrypto::RandomBitString(length);
        assert(length == identifier.size());

        uint8_t* buffer = (uint8_t*)get_buffer(module_inst, buffer_offset, length);
        if (buffer == NULL)
            return false;

        memcpy(buffer, identifier.data(), length);

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: sha256_hmac_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool sha256_hmac_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset, // uint8_t*
    const int32 msg_buffer_length, // size_t
    const int32 key_buffer_offset, // uint8_t*
    const int32 key_buffer_length, // size_t
    int32 hmac_buffer_pointer_offset, // uint8_t**
    int32 hmac_length_pointer_offset) // size_t*
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t* msg_buffer = (uint8_t*)get_buffer(module_inst, msg_buffer_offset, msg_buffer_length);
        if (msg_buffer == NULL)
            return false;

        ByteArray msg(msg_buffer, msg_buffer + msg_buffer_length);

        uint8_t* key_buffer = (uint8_t*)get_buffer(module_inst, key_buffer_offset, key_buffer_length);
        if (key_buffer == NULL)
            return false;

        ByteArray key(key_buffer, key_buffer + key_buffer_length);

        ByteArray hmac;
        pcrypto::SHA256HMAC(msg, key, hmac);
        if (hmac.size() == 0)
            return false;

        if (! save_buffer(module_inst, hmac, hmac_buffer_pointer_offset, hmac_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: sha384_hmac_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool sha384_hmac_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset, // uint8_t*
    const int32 msg_buffer_length, // size_t
    const int32 key_buffer_offset, // uint8_t*
    const int32 key_buffer_length, // size_t
    int32 hmac_buffer_pointer_offset, // uint8_t**
    int32 hmac_length_pointer_offset) // size_t*
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t* msg_buffer = (uint8_t*)get_buffer(module_inst, msg_buffer_offset, msg_buffer_length);
        if (msg_buffer == NULL)
            return false;

        ByteArray msg(msg_buffer, msg_buffer + msg_buffer_length);

        uint8_t* key_buffer = (uint8_t*)get_buffer(module_inst, key_buffer_offset, key_buffer_length);
        if (key_buffer == NULL)
            return false;

        ByteArray key(key_buffer, key_buffer + key_buffer_length);

        ByteArray hmac;
        pcrypto::SHA384HMAC(msg, key, hmac);
        if (hmac.size() == 0)
            return false;

        if (! save_buffer(module_inst, hmac, hmac_buffer_pointer_offset, hmac_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: sha512_hmac_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool sha512_hmac_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset, // uint8_t*
    const int32 msg_buffer_length, // size_t
    const int32 key_buffer_offset, // uint8_t*
    const int32 key_buffer_length, // size_t
    int32 hmac_buffer_pointer_offset, // uint8_t**
    int32 hmac_length_pointer_offset) // size_t*
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t* msg_buffer = (uint8_t*)get_buffer(module_inst, msg_buffer_offset, msg_buffer_length);
        if (msg_buffer == NULL)
            return false;

        ByteArray msg(msg_buffer, msg_buffer + msg_buffer_length);

        uint8_t* key_buffer = (uint8_t*)get_buffer(module_inst, key_buffer_offset, key_buffer_length);
        if (key_buffer == NULL)
            return false;

        ByteArray key(key_buffer, key_buffer + key_buffer_length);

        ByteArray hmac;
        pcrypto::SHA512HMAC(msg, key, hmac);
        if (hmac.size() == 0)
            return false;

        if (! save_buffer(module_inst, hmac, hmac_buffer_pointer_offset, hmac_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: ComputePasswordBasedKeyDerivation
 * ----------------------------------------------------------------- */
extern "C" bool sha512_pbkd_wrapper(
    wasm_exec_env_t exec_env,
    const int32 pw_buffer_offset, // char*
    const int32 pw_length,        // size_t
    const int32 salt_buffer_offset, // uint8_t*
    const int32 salt_length,        // size_t
    int32 key_buffer_pointer_offset, // uint8_t**
    int32 key_length_pointer_offset  // size_t*
    )
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        const char* pw_buffer = (const char*)get_buffer(module_inst, pw_buffer_offset, pw_length);
        if (pw_buffer == NULL)
            return false;

        const uint8_t* salt_buffer = (uint8_t*)get_buffer(module_inst, salt_buffer_offset, salt_length);
        if (salt_buffer == NULL)
            return false;

        std::string password(pw_buffer, pw_length);
        ByteArray salt(salt_buffer, salt_buffer + salt_length);

        ByteArray key;
        pcrypto::SHA512PasswordBasedKeyDerivation(password, salt, key);

        if (! save_buffer(module_inst, key, key_buffer_pointer_offset, key_length_pointer_offset))
            return false;

        return true;
    }
    catch (pdo::error::Error& e) {
        SAFE_LOG(PDO_LOG_ERROR, "failure in %s; %s", __FUNCTION__, e.what());
        return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }
}

/* ----------------------------------------------------------------- *
 * NAME: verify_sgx_report_wrapper(
 * ----------------------------------------------------------------- */
extern "C" bool verify_sgx_report_wrapper(
    wasm_exec_env_t exec_env,
    const int32 signing_cert_buffer_offset, // char*
    const int32 signing_cert_buffer_length, // size_t
    const int32 report_buffer_offset,       // char*
    const int32 report_buffer_length,       // size_t
    const int32 signature_buffer_offset,    // char*
    const int32 signature_buffer_length)    // size_t
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        const char* signing_cert_buffer =
            (const char*)get_buffer(module_inst, signing_cert_buffer_offset, signing_cert_buffer_length);
        if (signing_cert_buffer == NULL)
            return false;

        const char* report_buffer =
            (const char*)get_buffer(module_inst, report_buffer_offset, report_buffer_length);
        if (report_buffer == NULL)
            return false;

        const char* signature_buffer =
            (const char*)get_buffer(module_inst, signature_buffer_offset, signature_buffer_length);
        if (signature_buffer == NULL)
            return false;

        verify_status_t result = verify_ias_report_signature(signing_cert_buffer,
                                                             report_buffer, report_buffer_length,
                                                             signature_buffer, signature_buffer_length);

        return result == VERIFY_SUCCESS;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }

    return false;
}

/* ----------------------------------------------------------------- *
 * NAME: parse_sgx_report_wrapper(
 * ----------------------------------------------------------------- */
extern "C" bool parse_sgx_report_wrapper(
    wasm_exec_env_t exec_env,
    const int32 report_buffer_offset,       // char*
    const int32 report_buffer_length,       // size_t
    int32 msg_buffer_pointer_offset,
    int32 msg_length_pointer_offset)
{
    wasm_module_inst_t module_inst = wasm_runtime_get_module_inst(exec_env);
    try {
        uint8_t *pointer;
        ByteArray src;
        Base64EncodedString encoded;
        JSON_Status jret;

        const char* report_buffer =
            (const char*)get_buffer(module_inst, report_buffer_offset, report_buffer_length);
        if (report_buffer == NULL)
            return false;

        sgx_quote_t quote;
        int result = get_quote_from_report((const uint8_t*)report_buffer, report_buffer_length, &quote);
        if (result != 0)
            return false;

        // -------------------- build the quote --------------------
        JsonValue quote_information(json_value_init_object());
        if (quote_information.value == NULL)
            return false;

        JSON_Object* quote_object = json_value_get_object(quote_information);
        if (quote_object == NULL)
            return false;

        // ---------- version ----------
        jret = json_object_set_number(quote_object, "version", quote.version);
        if (jret != JSONSuccess)
            return false;

        // ---------- sign_type ----------
        jret = json_object_set_number(quote_object, "sign_type", quote.sign_type);
        if (jret != JSONSuccess)
            return false;

        // ---------- epid_group_id ----------
        pointer = (uint8_t*)&quote.epid_group_id;
        src.assign(pointer, pointer + sizeof(sgx_epid_group_id_t));
        encoded = ByteArrayToBase64EncodedString(src);

        jret = json_object_set_string(quote_object, "epid_group_id", encoded.c_str());
        if (jret != JSONSuccess)
            return false;

        // ---------- qe_svn ----------
        jret = json_object_set_number(quote_object, "qe_svn", quote.qe_svn);
        if (jret != JSONSuccess)
            return false;

        // ---------- pce_svn ----------
        jret = json_object_set_number(quote_object, "pce_svn", quote.pce_svn);
        if (jret != JSONSuccess)
            return false;

        // ---------- basename ----------
        pointer = (uint8_t*)&quote.basename;
        src.assign(pointer, pointer + sizeof(sgx_basename_t));
        encoded = ByteArrayToBase64EncodedString(src);

        jret = json_object_set_string(quote_object, "basename", encoded.c_str());
        if (jret != JSONSuccess)
            return false;

        // ---------- report body ----------
        JsonValue report_information(json_value_init_object());
        if (report_information.value == NULL)
            return false;

        JSON_Object* report_object = json_value_get_object(report_information);
        if (report_object == NULL)
            return false;

        // ---------- cpu_svn ----------
        pointer = (uint8_t*)&quote.report_body.cpu_svn;
        src.assign(pointer, pointer + sizeof(sgx_cpu_svn_t));
        encoded = ByteArrayToBase64EncodedString(src);

        jret = json_object_set_string(report_object, "cpu_svn", encoded.c_str());
        if (jret != JSONSuccess)
            return false;

        // ---------- mr_enclave ----------
        pointer = (uint8_t*)&quote.report_body.mr_enclave;
        src.assign(pointer, pointer + sizeof(sgx_measurement_t));
        encoded = ByteArrayToBase64EncodedString(src);

        jret = json_object_set_string(report_object, "mr_enclave", encoded.c_str());
        if (jret != JSONSuccess)
            return false;

        // ---------- mr_signer ----------
        pointer = (uint8_t*)&quote.report_body.mr_signer;
        src.assign(pointer, pointer + sizeof(sgx_measurement_t));
        encoded = ByteArrayToBase64EncodedString(src);

        jret = json_object_set_string(report_object, "mr_signer", encoded.c_str());
        if (jret != JSONSuccess)
            return false;

        // ---------- config_id ----------
        pointer = (uint8_t*)&quote.report_body.config_id;
        src.assign(pointer, pointer + sizeof(sgx_config_id_t));
        encoded = ByteArrayToBase64EncodedString(src);

        jret = json_object_set_string(report_object, "config_id", encoded.c_str());
        if (jret != JSONSuccess)
            return false;

        // ---------- report_data ----------
        pointer = (uint8_t*)&quote.report_body.report_data;
        src.assign(pointer, pointer + sizeof(sgx_report_data_t));
        encoded = ByteArrayToBase64EncodedString(src);

        jret = json_object_set_string(report_object, "report_data", encoded.c_str());
        if (jret != JSONSuccess)
            return false;

        // save the report body in the quote object
        jret = json_object_set_value(quote_object, "report_body", report_information.value);
        if (jret != JSONSuccess)
            return false;

        report_information.value = NULL;

        // serialize the result
        size_t serializedSize = json_serialization_size(quote_information);
        StringArray serialized_response(serializedSize);

        jret = json_serialize_to_buffer(quote_information,
                                        reinterpret_cast<char*>(&serialized_response[0]),
                                        serialized_response.size());

        if (jret != JSONSuccess)
            return false;

        if (! save_buffer(module_inst, serialized_response.str(), msg_buffer_pointer_offset, msg_length_pointer_offset))
            return false;
    }
    catch (...) {
        SAFE_LOG(PDO_LOG_ERROR, "unexpected failure in %s", __FUNCTION__);
        return false;
    }

    return true;
}
