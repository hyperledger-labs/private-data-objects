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
#include "crypto.h"
#include "state.h"
#include "log.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Local Functions
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static ByteArray to_privileged_key(const ByteArray& key)
{
    uint8_t access_right = 'P';
    ByteArray privileged_key = key;
    privileged_key.insert(privileged_key.begin(), access_right);
    return privileged_key;
}

static ByteArray to_unprivileged_key(const ByteArray& key)
{
    uint8_t access_right = 'p';
    ByteArray unprivileged_key = key;
    unprivileged_key.insert(unprivileged_key.begin(), access_right);
    return unprivileged_key;
}


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: Interpreter_KV
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo::state::Interpreter_KV::Interpreter_KV(ByteArray& id) : Basic_KV_Plus(id), kv_(id) {}

pdo::state::Interpreter_KV::Interpreter_KV(const ByteArray& id, const ByteArray& encryption_key)
    : Basic_KV_Plus(id), kv_(id, encryption_key) {}

pdo::state::Interpreter_KV::Interpreter_KV(const ByteArray& encryption_key)
    : Basic_KV_Plus(), kv_(encryption_key) {
}

pdo::state::Interpreter_KV::~Interpreter_KV()
{
    ByteArray id;
    kv_.Finalize(id);
}

void pdo::state::Interpreter_KV::Finalize(ByteArray& id)
{
    kv_.Finalize(id);
}

ByteArray pdo::state::Interpreter_KV::Get(const ByteArray& key)
{
    return kv_.Get(key);
}

void pdo::state::Interpreter_KV::Put(const ByteArray& key, const ByteArray& value)
{
    kv_.Put(key, value);
}

void pdo::state::Interpreter_KV::Delete(const ByteArray& key)
{
    kv_.Delete(key);
}

//########## FUNCTION BELOW ARE BASED ON THE ONES ABOVE################################################################

ByteArray pdo::state::Interpreter_KV::PrivilegedGet(const ByteArray& key)
{
    ByteArray privileged_key = to_privileged_key(key);
    return Get(privileged_key);
}

void pdo::state::Interpreter_KV::PrivilegedPut(const ByteArray& key, const ByteArray& value)
{
    ByteArray privileged_key = to_privileged_key(key);
    Put(privileged_key, value);
}

void pdo::state::Interpreter_KV::PrivilegedDelete(const ByteArray& key)
{
    ByteArray privileged_key = to_privileged_key(key);
    Delete(privileged_key);
}

ByteArray pdo::state::Interpreter_KV::UnprivilegedGet(const ByteArray& key)
{
    ByteArray unprivileged_key = to_unprivileged_key(key);
    return Get(unprivileged_key);
}

void pdo::state::Interpreter_KV::UnprivilegedPut(const ByteArray& key, const ByteArray& value)
{
    ByteArray unprivileged_key = to_unprivileged_key(key);
    Put(unprivileged_key, value);
}

void pdo::state::Interpreter_KV::UnprivilegedDelete(const ByteArray& key)
{
    ByteArray unprivileged_key = to_unprivileged_key(key);
    Delete(unprivileged_key);
}
