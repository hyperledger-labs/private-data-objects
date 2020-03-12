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

#include "crypto.h"
#include "error.h"
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
        encoded += '\0';

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
        encpriv += '\0';        // add a null terminator since this is a char*

        std::string encpub = pubkey.Serialize();
        encpub += '\0';         // add a null terminator since this is a char*

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
        encpriv += '\0';

        std::string encpub = pubkey.Serialize();
        encpub += '\0';

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
 * NAME: crypto_hash_wrapper
 * ----------------------------------------------------------------- */
extern "C" bool crypto_hash_wrapper(
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
        ByteArray hash = pcrypto::ComputeMessageHash(msg);
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
