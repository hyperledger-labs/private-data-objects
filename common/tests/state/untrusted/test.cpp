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

#include "packages/block_store/block_store.h"
#include "packages/block_store/lmdb_block_store.h"
#include "test_state_kv.h"
#include "log.h"

#define TEST_DATABASE_NAME ("utest.mdb")

/* Application entry */
int main(int argc, char* argv[])
{
    int result = 0;
    pdo::Log(PDO_LOG_DEBUG, "Test UNTRUSTED State API.\n");

    result = pdo::lmdb_block_store::BlockStoreInit(TEST_DATABASE_NAME);
    if (result != 0)
    {
        pdo::Log(PDO_LOG_ERROR, "Failed to initialize block store: %d\n", result);
        return -1;
    }

    pdo::Log(PDO_LOG_DEBUG, "Test State KV: start\n");
    test_state_kv();
    pdo::Log(PDO_LOG_DEBUG, "Test State KV:end\n");

    pdo::lmdb_block_store::BlockStoreClose();

    pdo::Log(PDO_LOG_DEBUG, "Test UNTRUSTED State API SUCCESSFUL!\n");
    return 0;
}
