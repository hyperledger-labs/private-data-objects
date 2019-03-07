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
#include <stdio.h>
#include <unistd.h>

#include "log.h"

#include "packages/block_store/block_store.h"
#include "packages/block_store/lmdb_block_store.h"
#include "test_state_kv.h"

#define TEST_DATABASE_NAME "utest.mdb"
#define LOCK_EXTENSION "-lock"
#define TEST_DATABASE_LOCK_NAME TEST_DATABASE_NAME LOCK_EXTENSION

/* Application entry */
int main(int argc, char* argv[])
{
    SAFE_LOG(PDO_LOG_DEBUG, "Test UNTRUSTED State API.\n");

    pdo::lmdb_block_store::BlockStoreOpen(TEST_DATABASE_NAME);

    SAFE_LOG(PDO_LOG_DEBUG, "Test State KV: start\n");
    test_state_kv();
    SAFE_LOG(PDO_LOG_DEBUG, "Test State KV:end\n");

    pdo::lmdb_block_store::BlockStoreClose();

    // Remove test db as docker builds will struggle with this huge sparse file ..
    unlink(TEST_DATABASE_NAME);
    unlink(TEST_DATABASE_LOCK_NAME);

    SAFE_LOG(PDO_LOG_DEBUG, "Test UNTRUSTED State API SUCCESSFUL!\n");
    return 0;
}
