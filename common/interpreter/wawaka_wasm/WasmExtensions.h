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

/*
This file should be included by contracts to access native functions
provided by the Wawaka interpreter.
*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include <stdio.h>

// From WasmStateExtensions
bool key_value_set(
    const uint8_t* key_buffer,
    const size_t key_buffer_length,
    const uint8_t* val_buffer,
    const size_t val_buffer_length);

bool key_value_get(
    const uint8_t* key_buffer,
    const size_t key_buffer_length,
    uint8_t** val_buffer_pointer,
    size_t* val_length_pointer);

// From WasmCryptoExtensions
bool b64_encode(
    const uint8_t* decode_buffer,
    const size_t decode_length,
    char** encode_buffer,
    size_t* encode_length);

bool b64_decode(
    const char* encode_buffer,
    const size_t  encode_length,
    uint8_t** decode_buffer,
    size_t* decode_length);

bool ecdsa_create_signing_keys(
    char** private_buffer_pointer,
    size_t* private_length_pointer,
    char** public_buffer_pointer,
    size_t* public_length_pointer);

bool ecdsa_sign_message(
    const uint8_t* msg_buffer,
    const size_t msg_length,
    const char* key_buffer,
    const size_t key_length,
    uint8_t** sig_buffer_pointer,
    size_t* sig_length_pointer);

bool ecdsa_verify_signature(
    const uint8_t* msg_buffer,
    const size_t msg_length,
    const char* key_buffer,
    const size_t key_length,
    const uint8_t* sig_buffer,
    const size_t sig_length);

bool aes_generate_key(
    uint8_t** buffer_pointer,
    size_t* buffer_length_pointer);

bool aes_generate_iv(
    const uint8_t* buffer,
    const size_t length,
    uint8_t** iv_buffer_pointer,
    size_t* iv_length_pointer);

bool aes_encrypt_message(
    const uint8_t* msg_buffer,
    const size_t msg_length,
    const uint8_t* key_buffer,
    const size_t key_length,
    const uint8_t* iv_buffer,
    const size_t iv_length,
    uint8_t** cipher_buffer_pointer,
    size_t* cipher_length_pointer);

bool aes_decrypt_message(
    const uint8_t* cipher_buffer,
    const size_t cipher_length,
    const uint8_t* key_buffer,
    const size_t key_length,
    const uint8_t* iv_buffer,
    const size_t iv_length,
    uint8_t** msg_buffer_pointer,
    size_t* msg_length_pointer);

bool rsa_generate_keys(
    char** private_buffer_pointer,
    size_t* private_length_pointer,
    char** public_buffer_pointer,
    size_t* public_length_pointer);

bool rsa_encrypt_message(
    const uint8_t* msg_buffer,
    const size_t msg_length,
    const char* key_buffer,
    const size_t key_length,
    uint8_t** cipher_buffer_pointer,
    size_t* cipher_length_pointer);

bool rsa_decrypt_message(
    const uint8_t* cipher_buffer,
    const size_t cipher_length,
    const char* key_buffer,
    const size_t key_length,
    uint8_t** msg_buffer_pointer,
    size_t* msg_length_pointer);

bool crypto_hash(
    const uint8_t* msg_buffer,
    const size_t msg_length,
    uint8_t** hash_buffer_pointer,
    size_t* hash_length_pointer);

bool random_identifier(
    const size_t length,
    uint8_t* buffer_pointer);

// From WasmExtensions
bool contract_log(
    const uint32_t loglevel,
    const char *buffer);

int simple_hash(uint8_t *buffer, const size_t buflen);

#ifdef __cplusplus
}
#endif

#define CONTRACT_SAFE_LOG(LEVEL, FMT, ...) \
    {                                      \
        char buf[512];                          \
        snprintf(buf, 512, FMT, ##__VA_ARGS__); \
        contract_log(LEVEL, buf);               \
    }                                           \
