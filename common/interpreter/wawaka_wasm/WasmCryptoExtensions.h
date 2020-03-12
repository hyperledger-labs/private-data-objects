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

#include "bh_platform.h"
#include "wasm_export.h"
#include "lib_export.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
extern "C" bool b64_encode_wrapper(
    wasm_exec_env_t exec_env,
    const int32 dec_buffer_offset,
    const int32 dec_length,
    int32 enc_buffer_pointer_offset,
    int32 enc_length_pointer_offset);

extern "C" bool b64_decode_wrapper(
    wasm_exec_env_t exec_env,
    const int32 enc_buffer_offset,
    const int32 enc_length,
    int32 dec_buffer_pointer_offset,
    int32 dec_length_pointer_offset);

extern "C" bool ecdsa_create_signing_keys_wrapper(
    wasm_exec_env_t exec_env,
    const int32 private_buffer_pointer_offset,
    const int32 private_length_pointer_offset,
    const int32 public_buffer_pointer_offset,
    const int32 public_length_pointer_offset);

extern "C" bool ecdsa_sign_message_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset,
    const int32 msg_length,
    const int32 key_buffer_offset,
    const int32 key_length,
    int32 sig_buffer_pointer_offset,
    int32 sig_length_pointer_offset);

extern "C" bool ecdsa_verify_signature_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset,
    const int32 msg_length,
    const int32 key_buffer_offset,
    const int32 key_length,
    const int32 sig_buffer_offset,
    const int32 sig_length);

extern "C" bool aes_generate_key_wrapper(
    wasm_exec_env_t exec_env,
    int32 key_buffer_pointer_offset,
    int32 key_length_pointer_offset);

extern "C" bool aes_generate_iv_wrapper(
    wasm_exec_env_t exec_env,
    const int32 buffer_offset,
    const int32 buffer_length,
    int32 iv_buffer_pointer_offset,
    int32 iv_length_pointer_offset);

extern "C" bool aes_encrypt_message_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset,
    const int32 msg_length,
    const int32 key_buffer_offset,
    const int32 key_length,
    const int32 iv_buffer_offset,
    const int32 iv_length,
    int32 cipher_buffer_pointer_offset,
    int32 cipher_length_pointer_offset);

extern "C" bool aes_decrypt_message_wrapper(
    wasm_exec_env_t exec_env,
    const int32 cipher_buffer_offset,
    const int32 cipher_length,
    const int32 key_buffer_offset,
    const int32 key_length,
    const int32 iv_buffer_offset,
    const int32 iv_length,
    int32 msg_buffer_pointer_offset,
    int32 msg_length_pointer_offset);

extern "C" bool rsa_generate_keys_wrapper(
    wasm_exec_env_t exec_env,
    int32 private_buffer_pointer_offset,
    int32 private_length_pointer_offset,
    int32 public_buffer_pointer_offset,
    int32 public_length_pointer_offset);

extern "C" bool rsa_encrypt_message_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset,
    const int32 msg_length,
    const int32 key_buffer_offset,
    const int32 key_length,
    int32 cipher_buffer_pointer_offset,
    int32 cipher_length_pointer_offset);

extern "C" bool rsa_decrypt_message_wrapper(
    wasm_exec_env_t exec_env,
    const int32 cipher_buffer_offset,
    const int32 cipher_length,
    const int32 key_buffer_offset,
    const int32 key_length,
    int32 msg_buffer_pointer_offset,
    int32 msg_length_pointer_offset);

extern "C" bool crypto_hash_wrapper(
    wasm_exec_env_t exec_env,
    const int32 msg_buffer_offset,
    const int32 msg_buffer_length,
    int32 hash_buffer_pointer_offset,
    int32 hash_length_pointer_offset);

extern "C" bool random_identifier_wrapper(
    wasm_exec_env_t exec_env,
    const int32 length,
    int32 buffer_offset);
