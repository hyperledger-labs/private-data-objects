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
#include "basic_kv.h"

//TODO move the definition somewhere else
#define PORTAGE_ON_MONKV

#ifdef PORTAGE_ON_MONKV
#include "serial_kv.h"
#endif

pdo::state::Interpreter_KV::Interpreter_KV(ByteArray& id) : Basic_KV(id) {
#ifdef PORTAGE_ON_MONKV
    Serial_KV* serial_kv = new pdo::state::Serial_KV(id);
    kv_ = serial_kv;
#endif
}

pdo::state::Interpreter_KV::~Interpreter_KV() {
    delete kv_;
}

void pdo::state::Interpreter_KV::Uninit(ByteArray& id) {
    kv_->Uninit(id);
}

ByteArray pdo::state::Interpreter_KV::Get(ByteArray& key) {
    return kv_->Get(key);
}

void pdo::state::Interpreter_KV::Put(ByteArray& key, ByteArray& value) {
    kv_->Put(key, value);
}

void pdo::state::Interpreter_KV::Delete(ByteArray& key) {
    kv_->Delete(key);
}
