/*
 * Copyright 2024 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test.h"
#include <string>
#include "error.h"
#include "logging.h"
#include "test-defines.h"
#include "test-utils.h"

#include <stdbool.h>

#include "attestation_tags.h"
#include "verify-evidence.h"

#include "sgx_eid.h"
#include "sgx_error.h"
#include "sgx_urts.h"
#include "test-defines.h"
#include "test-utils.h"
#include "test_verify_enclave_u.h"

bool test()
{
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_enclave_id_t global_eid = 0;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(VERIFY_ENCLAVE_FILENAME, 1, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        puts("error creating enclave");
        exit(-1);
    }

    uint32_t buffer_length = 1 << 20;
    char buffer[buffer_length];
    uint32_t filled_size;
    std::string jsonevidence;
    std::string expected_statement;
    std::string expected_code_id;
    std::string wrong_expected_statement;
    std::string wrong_expected_code_id;

    COND2LOGERR(!load_file(EVIDENCE_FILE, buffer, buffer_length, &filled_size),
        "can't read input evidence " EVIDENCE_FILE);
    jsonevidence = std::string(buffer, filled_size);

    COND2LOGERR(!load_file(STATEMENT_FILE, buffer, buffer_length, &filled_size),
        "can't read input statement " STATEMENT_FILE);
    expected_statement = std::string(buffer, filled_size);

    COND2LOGERR(!load_file(CODE_ID_FILE, buffer, buffer_length, &filled_size),
        "can't read input code id " CODE_ID_FILE);
    expected_code_id = std::string(buffer, filled_size);

    wrong_expected_statement = std::string("wrong statement");
    wrong_expected_code_id =
        std::string("BADBADBADBAD9E317C4F7312A0D644FFC052F7645350564D43586D8102663358");

    bool b, expected_b;
    // test normal situation
    expected_b = true; b = !expected_b;
    ret = verify_ev(global_eid, &b,
            (uint8_t*)jsonevidence.c_str(), jsonevidence.length(),
            (uint8_t*)expected_statement.c_str(), expected_statement.length(),
            (uint8_t*)expected_code_id.c_str(), expected_code_id.length());
    COND2LOGERR(ret != SGX_SUCCESS, "sgx error: %x", ret);
    COND2LOGERR(b != expected_b, "correct evidence failed");

    // this test succeeds for simulated attestations, and fails for real ones
    // test with wrong statement
    expected_b = (jsonevidence.find(SIMULATED_TYPE_TAG) == std::string::npos ? false : true);
    b = !expected_b;
    if (expected_b == false)
    {
        LOG_WARNING("next test expected to fail");
    }
    ret = verify_ev(global_eid, &b,
            (uint8_t*)jsonevidence.c_str(), jsonevidence.length(),
            (uint8_t*)wrong_expected_statement.c_str(), wrong_expected_statement.length(),
            (uint8_t*)expected_code_id.c_str(), expected_code_id.length());
    COND2LOGERR(ret != SGX_SUCCESS, "sgx error: %x", ret);
    COND2LOGERR(b != expected_b, "evidence with bad statement succeeded");

    // this test succeeds for simulated attestations, and fails for real ones
    // test with wrong code id
    expected_b = (jsonevidence.find(SIMULATED_TYPE_TAG) == std::string::npos ? false : true);
    b = !expected_b;
    if (expected_b == false)
    {
        LOG_WARNING("next test expected to fail");
    }
    ret = verify_ev(global_eid, &b,
            (uint8_t*)jsonevidence.c_str(), jsonevidence.length(),
        (uint8_t*)expected_statement.c_str(), expected_statement.length(),
        (uint8_t*)wrong_expected_code_id.c_str(), wrong_expected_code_id.length());
    COND2LOGERR(ret != SGX_SUCCESS, "sgx error: %x", ret);
    COND2LOGERR(b != expected_b, "evidence with bad code id succeeded");

    sgx_destroy_enclave(global_eid);

    LOG_INFO("Test Successful\n");
    return true;

err:
    return false;
}
