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

#include <stdlib.h>
#include <string>

#include "error.h"
#include "pdo_error.h"
#include "types.h"
#include "packages/base64/base64.h"
#include "packages/block_store/block_store.h"

#include "block_store.h"
#include "swig_utils.h"


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void block_store_init()
{
    pdo_err_t presult = pdo::block_store::BlockStoreInit();
    ThrowPDOError(presult);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int block_store_head(
    const std::string& key_b64
    )
{
    ByteArray raw_key = base64_decode(key_b64);

    return pdo::block_store::BlockStoreHead(raw_key);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::string block_store_get(
    const std::string& key_b64
    )
{
    ByteArray raw_key = base64_decode(key_b64);
    ByteArray raw_value;

    pdo_err_t presult = pdo::block_store::BlockStoreGet(raw_key, raw_value);
    ThrowPDOError(presult);

    return base64_encode(raw_value);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void block_store_put(
    const std::string& key_b64,
    const std::string& value_b64
    )
{
    ByteArray raw_key = base64_decode(key_b64);
    ByteArray raw_value = base64_decode(value_b64);

    pdo_err_t presult = pdo::block_store::BlockStorePut(raw_key, raw_value);
    ThrowPDOError(presult);
}
