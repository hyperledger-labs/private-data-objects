/*
 * Copyright 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "verify-evidence.h"
#include <string.h>
#include <string>
#include "attestation_tags.h"
#include "error.h"
#include "logging.h"
#include "types/types.h"
#include "verify-ias-evidence.h"
#include "verify-dcap-evidence.h"
#include "verify-dcap-direct-evidence.h"

// < JSON include
#define JSON_HAS_CPP_11
#define JSON_NO_IO 1
#include <errno.h>
#include "nlohmann/json.hpp"
using json = nlohmann::json;
// JSON include >

bool verify_evidence(uint8_t* evidence,
    uint32_t evidence_length,
    uint8_t* expected_statement,
    uint32_t expected_statement_length,
    uint8_t* expected_code_id,
    uint32_t expected_code_id_length)
{
    bool ret = false;
    json root;
    std::string attestation_type;
    std::string evidence_field;
    std::string evidence_str((char*)evidence, evidence_length);
    ByteArray ba_expected_statement(
        expected_statement, expected_statement + expected_statement_length);
    ByteArray ba_expected_code_id(expected_code_id, expected_code_id + expected_code_id_length);

    CATCH(ret, root = json::parse(evidence_str));
    COND2LOGERR(!ret, "invalid evidence json");

    CATCH(ret, attestation_type = root[ATTESTATION_TYPE_TAG].template get<std::string>());
    COND2LOGERR(!ret, "invalid (or missing) attestation type field");

    CATCH(ret, evidence_field = root[EVIDENCE_TAG].template get<std::string>());
    COND2LOGERR(!ret, "invalid evidence field");

    if (0 == attestation_type.compare(SIMULATED_TYPE_TAG))
    {
        // nothing to check
        ret = true;
    }

    if (0 == attestation_type.compare(EPID_LINKABLE_TYPE_TAG) ||
        0 == attestation_type.compare(EPID_UNLINKABLE_TYPE_TAG))
    {
        ByteArray ba_evidence(evidence_field.begin(), evidence_field.end());
        bool b = verify_ias_evidence(ba_evidence, ba_expected_statement, ba_expected_code_id);
        COND2ERR(b == false);
        ret = true;
    }

    if (0 == attestation_type.compare(DCAP_SGX_TYPE_TAG))
    {
        ByteArray ba_evidence(evidence_field.begin(), evidence_field.end());
        bool b = verify_dcap_evidence(ba_evidence, ba_expected_statement, ba_expected_code_id);
        COND2ERR(b == false);
        ret = true;
    }

    if (0 == attestation_type.compare(DCAP_DIRECT_SGX_TYPE_TAG))
    {
        ByteArray ba_evidence(evidence_field.begin(), evidence_field.end());
        bool b = verify_dcap_direct_evidence(ba_evidence, ba_expected_statement, ba_expected_code_id);
        COND2ERR(b == false);
        ret = true;
    }

    COND2LOGERR(ret == false, "bad attestation type: %s", attestation_type.c_str());

    return true;

err:
    return false;
}
