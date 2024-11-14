/*
 * Copyright 2024 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "stdbool.h"
#include "verify-evidence.h"
#include "logging.h"
#include "test_verify_enclave_t.h"


bool verify_ev(uint8_t* evidence,
    uint32_t evidence_length,
    uint8_t* expected_statement,
    uint32_t expected_statement_length,
    uint8_t* expected_code_id,
    uint32_t expected_code_id_length)
{
    return verify_evidence(
            evidence,
            evidence_length,
            expected_statement,
            expected_statement_length,
            expected_code_id,
            expected_code_id_length);
}
