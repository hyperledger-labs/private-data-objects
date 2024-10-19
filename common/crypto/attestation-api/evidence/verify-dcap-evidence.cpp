/*
 * Copyright 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <algorithm>
#include "types/types.h"
#include "crypto/verify_ita_token/verify-token.h"
#include "error.h"
#include "logging.h"
#include "crypto/sha256.h"
#include "attestation_tags.h"

// < JSON include
#define JSON_HAS_CPP_11
#define JSON_NO_IO 1
#include <errno.h>
#include "nlohmann/json.hpp"
using json = nlohmann::json;
// JSON include >


bool verify_dcap_evidence(ByteArray& evidence, ByteArray& expected_statement, ByteArray& expected_code_id)
{
    std::string evidence_str((char*)evidence.data(), evidence.size());
    std::string ita_token_str;
    std::string ita_payload_str;
    verify_status_t vs;
    bool b;

    LOG_DEBUG("evidence: %s", evidence_str.c_str());

    // get ITA token
    {
        //parse evidence
        json root;
        CATCH(b, root = json::parse(evidence_str));
        COND2LOGERR(!b, "bad dcap evidence json");

        //get ita token
        CATCH(b, ita_token_str = root[ITA_TOKEN_TAG].template get<std::string>());
        COND2LOGERR(!b, "no ita token in dcap verification");
        LOG_DEBUG("ita token: %s\n", ita_token_str.c_str());
    }

    // verify ITA token signature
    {
        //get token payload
        b = get_token_payload(ita_token_str, ita_payload_str);
        COND2LOGERR(!b, "cannot get ita payload");

        //verify ita token
        vs = verify_ita_token_signature(ita_token_str);
        COND2LOGERR(vs == VERIFY_FAILURE, "token verification failed");        
    }

    // verify mrenclave and statement
    {
        json root;
        CATCH(b, root = json::parse(ita_payload_str));
        COND2LOGERR(!b, "bad ita payload json");

        //prepare external mrenclave
        std::string sgx_mrenclave;
        CATCH(b, sgx_mrenclave = root["sgx_mrenclave"].template get<std::string>());
        COND2LOGERR(!b, "no sgx_mrenclave in ita payload");
        COND2LOGERR(sgx_mrenclave.length() == 0, "sgx_mrenclave is empty");
        std::transform(sgx_mrenclave.begin(), sgx_mrenclave.end(), sgx_mrenclave.begin(), ::toupper);
        LOG_DEBUG("sgx_mrenclave: %s\n", sgx_mrenclave.c_str());

        //prepare expected mrenclave
        std::string expected_hex_id((char*)expected_code_id.data(), expected_code_id.size());
        std::transform(expected_hex_id.begin(), expected_hex_id.end(), expected_hex_id.begin(), ::toupper);

        //check mrenclaves
        COND2LOGERR(0 != sgx_mrenclave.compare(expected_hex_id),
                "expected code id %s mismatch %s", expected_hex_id.c_str(), sgx_mrenclave.c_str());

        //prepare external report data
        std::string sgx_report_data;
        CATCH(b, sgx_report_data = root["sgx_report_data"].template get<std::string>());
        COND2LOGERR(!b, "no sgx_report_data in ita payload");
        COND2LOGERR(sgx_report_data.length() == 0, "sgx_report_data is empty");
        std::transform(sgx_report_data.begin(), sgx_report_data.end(), sgx_report_data.begin(), ::toupper);
        LOG_DEBUG("sgx_report_data: %s\n", sgx_report_data.c_str());

        //prepare expected report data
        ByteArray hash;
        std::string expected_hex_report_data_str;
        COND2ERR(false == SHA256(expected_statement, hash));
        expected_hex_report_data_str = ByteArrayToHexEncodedString(hash);
        expected_hex_report_data_str.append(expected_hex_report_data_str.length(), '0'); //double length with 0s
        std::transform(expected_hex_report_data_str.begin(), expected_hex_report_data_str.end(), expected_hex_report_data_str.begin(), ::toupper);

        COND2LOGERR(0 != sgx_report_data.compare(expected_hex_report_data_str),
            "expected statement %s mismatch %s", expected_hex_report_data_str.c_str(), sgx_report_data.c_str());
    }

    return true;

err:
    return false;
}
