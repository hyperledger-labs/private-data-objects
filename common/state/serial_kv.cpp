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

#include "error.h"
#include "pdo_error.h"
#include "state.h"

#ifdef DEBUG
    #define SAFE_LOG(LEVEL, FMT, ...) Log(LEVEL, FMT, ##__VA_ARGS__)
#else // DEBUG not defined
    #define SAFE_LOG(LEVEL, FMT, ...)
#endif // DEBUG

pdo::state::Serial_KV::Serial_KV(ByteArray& id) : Basic_KV(id) {
    g_sal.open(id, &handle); 
}

pdo::state::Serial_KV::~Serial_KV() {
    ByteArray id;
    if(handle) {
        g_sal.close(&handle, &id);
    }
}

void pdo::state::Serial_KV::Uninit(ByteArray& id) {
    if(handle) {
        g_sal.close(&handle, &id);
    }
}

ByteArray pdo::state::Serial_KV::Get(ByteArray& key) {
    g_sal.seek(handle, INT64_MIN);
    ByteArray ks, vs, k, v, none;
    SAFE_LOG(PDO_LOG_DEBUG, "serial_kv get key: %s\n", ByteArrayToHexEncodedString(key).c_str());
    while(1) {
        if(STATE_EOD == g_sal.read(handle, sizeof(size_t), ks))
            break;
        g_sal.read(handle, sizeof(size_t), vs);
        size_t ksize = *((size_t*)ks.data());
        size_t vsize = *((size_t*)vs.data());
        g_sal.read(handle, ksize, k);
        g_sal.read(handle, vsize, v);
        if(k == key) {
            return v;
        }
        ks.clear();
        vs.clear();
        k.clear();
        v.clear();
    }
    return none;
}

void pdo::state::Serial_KV::Put(ByteArray& key, ByteArray& value) {
    SAFE_LOG(PDO_LOG_DEBUG, "serial_kv put key: %s\n", ByteArrayToHexEncodedString(key).c_str());
    SAFE_LOG(PDO_LOG_DEBUG, "serial_kv put val: %s\n", ByteArrayToHexEncodedString(value).c_str());
    g_sal.seek(handle, INT64_MAX);
    size_t key_size = key.size();
    size_t value_size = value.size();
    ByteArray baks((uint8_t*)&key_size, (uint8_t*)&key_size+sizeof(key_size));
    ByteArray bavs((uint8_t*)&value_size, (uint8_t*)&value_size+sizeof(value_size));
    g_sal.write(handle, baks);
    g_sal.write(handle, bavs);
    g_sal.write(handle, key);
    g_sal.write(handle, value);
}

void pdo::state::Serial_KV::Delete(ByteArray& key) {
    SAFE_LOG(PDO_LOG_DEBUG, "serial_kv del key: %s\n", ByteArrayToHexEncodedString(key).c_str());
    ByteArray value = Get(key);
    if(value.empty()) { //no key found
        return;
    }
    //Assumption: cursor is right after key-value pair
    int64_t kv_pair_size = 2*(sizeof(size_t)) + key.size() + value.size();
    //shift back kv_pair_size bytes everything coming after cursor
    ByteArray buf;
    while(1) {
        if(g_sal.read(handle, 1024, buf) == STATE_EOD && buf.empty()) {
            break;
        }
        g_sal.seek(handle, - kv_pair_size - buf.size());
        g_sal.write(handle, buf);
        g_sal.seek(handle, + kv_pair_size);
        buf.clear();
    }
    //truncate the state to reduce the size
    g_sal.seek(handle, - kv_pair_size);
    g_sal.truncate_here(handle);
}
