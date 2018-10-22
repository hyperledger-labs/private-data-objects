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
#include "test_state_kv.h"

/* Application entry */
int main(int argc, char *argv[])
{
    int result = 0;
    printf("Test UNTRUSTED State API.\n");

    pdo::block_store::BlockStoreInit();

    printf("Test State KV: start\n");
    test_state_kv();
    printf("Test State KV:end\n");

    if (result != 0)
    {
        printf("ERROR: UNTRUSTED State API test FAILED.\n");
        return -1;
    }

    printf("Test UNTRUSTED State API SUCCESSFUL!\n");
    return 0;
}
