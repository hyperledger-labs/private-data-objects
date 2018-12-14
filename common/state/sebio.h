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

#pragma once

#include "state.h"
#include "types.h"

typedef enum { SEBIO_NO_CRYPTO, SEBIO_AES_GCM } sebio_crypto_algo_e;

typedef struct
{
    ByteArray key;
    sebio_crypto_algo_e crypto_algo;
    // The sebio context includes two function pointer that sebio will call
    // for fetching and evicting blocks.
    // This allows the caller to specify custom functions if necessary,
    // and default functions are provided below.
    state_status_t (*f_sebio_fetch)(const pdo::state::StateBlockId& block_id,
        sebio_crypto_algo_e crypto_algo,
        pdo::state::StateBlock& block);
    state_status_t (*f_sebio_evict)(const pdo::state::StateBlockId& block_id,
        sebio_crypto_algo_e crypto_algo,
        ByteArray& idOnEviction);
} sebio_ctx_t;

state_status_t sebio_set(sebio_ctx_t ctx);

state_status_t sebio_fetch(const pdo::state::StateBlockId& block_id,
    sebio_crypto_algo_e crypto_algo,
    pdo::state::StateBlock& block);

state_status_t sebio_evict(
    const pdo::state::StateBlock& block, sebio_crypto_algo_e crypto_algo, ByteArray& idOnEviction);
