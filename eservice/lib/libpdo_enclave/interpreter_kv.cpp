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

#include "interpreter_kv.h"
#include "state.h"
#include "crypto.h"

#define INTERPRETER_KV_KEY_SIZE_BYTES (SHA256_DIGEST_LENGTH /2) //16 bytes == 128bits

pdo::state::Interpreter_KV::Interpreter_KV(ByteArray& id) : Basic_KV_Plus(id) {
}

pdo::state::Interpreter_KV::Interpreter_KV(ByteArray& id, const ByteArray& encryption_key) : Interpreter_KV(id) {
    ByteArray key = encryption_key;
    State_KV* state_kv = new pdo::state::State_KV(id, key, INTERPRETER_KV_KEY_SIZE_BYTES);
    kv_ = state_kv;
}

ByteArray pdo::state::Interpreter_KV::to_kvkey(ByteArray& key) {
    ByteArray kvKey = pdo::crypto::ComputeMessageHash(key);
    kvKey.resize(INTERPRETER_KV_KEY_SIZE_BYTES);
    return kvKey;
}

pdo::state::Interpreter_KV::~Interpreter_KV() {
    if(kv_ != NULL) {
        delete kv_;
        kv_ = NULL;
    }
}

void pdo::state::Interpreter_KV::Uninit(ByteArray& id) {
    kv_->Uninit(id);
}

ByteArray pdo::state::Interpreter_KV::Get(ByteArray& key) {
    ByteArray kvkey = to_kvkey(key);
    return kv_->Get(kvkey);
}

void pdo::state::Interpreter_KV::Put(ByteArray& key, ByteArray& value) {
    ByteArray kvkey = to_kvkey(key);
    kv_->Put(kvkey, value);
}

void pdo::state::Interpreter_KV::Delete(ByteArray& key) {
    ByteArray kvkey = to_kvkey(key);
    kv_->Delete(kvkey);
}

ByteArray to_privileged_key(ByteArray& key) {
    uint8_t access_right = 'P';
    ByteArray privileged_key = key;
    privileged_key.insert(privileged_key.begin(), access_right);
    return privileged_key;
}

ByteArray to_unprivileged_key(ByteArray& key) {
    uint8_t access_right = 'p';
    ByteArray unprivileged_key = key;
    unprivileged_key.insert(unprivileged_key.begin(), access_right);
    return unprivileged_key;
}

ByteArray pdo::state::Interpreter_KV::PrivilegedGet(ByteArray& key) {
    ByteArray privileged_key = to_privileged_key(key);
    ByteArray kvkey = to_kvkey(privileged_key);
    return kv_->Get(kvkey);
}

void pdo::state::Interpreter_KV::PrivilegedPut(ByteArray& key, ByteArray& value) {
    ByteArray privileged_key = to_privileged_key(key);
    ByteArray kvkey = to_kvkey(privileged_key);
    kv_->Put(kvkey, value);
}

ByteArray pdo::state::Interpreter_KV::UnprivilegedGet(ByteArray& key) {
    ByteArray unprivileged_key = to_unprivileged_key(key);
    ByteArray kvkey = to_kvkey(unprivileged_key);
    return kv_->Get(kvkey);
}

void pdo::state::Interpreter_KV::UnprivilegedPut(ByteArray& key, ByteArray& value) {
    ByteArray unprivileged_key = to_unprivileged_key(key);
    ByteArray kvkey = to_kvkey(unprivileged_key);
    kv_->Put(kvkey, value);
}
