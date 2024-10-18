/*
 * Copyright 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sgx_quote.h"
#include "sgx_utils.h"

typedef struct
{
    sgx_spid_t spid;
    ByteArray sig_rl;
    uint32_t sign_type;
} epid_state_t;

bool init_epid(uint8_t* params, uint32_t params_length, epid_state_t* state);

bool get_epid_attestation(uint8_t* statement,
    uint32_t statement_length,
    epid_state_t* state,
    std::string& b64attestation);
