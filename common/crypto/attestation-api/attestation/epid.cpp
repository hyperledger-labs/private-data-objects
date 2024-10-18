/*
 * Copyright 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <string>
#include "sgx_quote.h"
#include "sgx_utils.h"
#include "error.h"
#include "logging.h"
#include "attestation_tags.h"
#include "types/types.h"
#include "crypto/sha256.h"
#include "base64/base64.h"
#include "epid.h"

// < JSON include
#define JSON_HAS_CPP_11
#define JSON_NO_IO 1
#include <errno.h>
#include "nlohmann/json.hpp"
using json = nlohmann::json;
// JSON include >

/**********************************************************************************************************************
 * C prototype declarations for the ocalls
 * *******************************************************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t ocall_init_quote(
    uint8_t* target, uint32_t target_len, uint8_t* egid, uint32_t egid_len, uint32_t* sgxret);
sgx_status_t ocall_get_quote(uint8_t* spid,
    uint32_t spid_len,
    uint8_t* sig_rl,
    uint32_t sig_rl_len,
    uint32_t sign_type,
    uint8_t* report,
    uint32_t report_len,
    uint8_t* quote,
    uint32_t max_quote_len,
    uint32_t* actual_quote_len,
    uint32_t* sgxret);

#ifdef __cplusplus
}
#endif /* __cplusplus */


/**********************************************************************************************************************
 * EPID Attestation APIs
 * *******************************************************************************************************************/

bool init_epid(uint8_t* params, uint32_t params_length, epid_state_t* state)
{
    if(params == NULL || state == NULL)
    {
        LOG_ERROR("bad params");
        return false;
    }

    // open json
    bool ret = false;
    json root;
    std::string params_string((char*)params, params_length);
    CATCH(ret, root = json::parse(params_string));
    COND2LOGERR(!ret, "invalid attestation params");

    {  // set attestation type
        std::string attestation_type;
        CATCH(ret, attestation_type = root[ATTESTATION_TYPE_TAG].template get<std::string>());
        COND2LOGERR(!ret, "invalid attestation type field");

        state->sign_type = -1;
        if (attestation_type.compare(EPID_LINKABLE_TYPE_TAG) == 0)
        {
            state->sign_type = SGX_LINKABLE_SIGNATURE;
        }

        if (attestation_type.compare(EPID_UNLINKABLE_TYPE_TAG) == 0)
        {
            state->sign_type = SGX_UNLINKABLE_SIGNATURE;
        }

        COND2LOGERR(state->sign_type == -1, "wrong attestation type");
    }

    {  // set SPID
        HexEncodedString hex_spid;
        CATCH(ret, hex_spid = root[SPID_TAG].template get<std::string>());
        COND2LOGERR(!ret, "invalid spid");
        COND2LOGERR(hex_spid.length() != sizeof(sgx_spid_t) * 2, "wrong spid length");
        
        // translate hex spid to binary
        ByteArray ba = HexEncodedStringToByteArray(hex_spid);
        memcpy(state->spid.id, ba.data(), ba.size());
    }

    {  // set sig_rl
        std::string sig_rl_str;
        CATCH(ret, sig_rl_str = root[SIG_RL_TAG].template get<std::string>());
        COND2LOGERR(!ret, "invalid sig_rl");
        state->sig_rl = ByteArray(sig_rl_str.begin(), sig_rl_str.end());
    }

    return true;

err:
    return false;    
}

bool get_epid_attestation(uint8_t* statement,
    uint32_t statement_length,
    epid_state_t* state,
    std::string& b64attestation)
{
    sgx_report_t report;
    sgx_report_data_t report_data = {0};
    sgx_target_info_t qe_target_info = {0};
    sgx_epid_group_id_t egid = {0};
    uint32_t ret;
    uint32_t attestation_length_max =  (1<<12); // 4K
    uint32_t attestation_length;
    uint8_t attestation[attestation_length_max];

    ByteArray ba_statement(statement, statement + statement_length);
    ByteArray rd;
    COND2ERR(false == SHA256(ba_statement, rd));

    ocall_init_quote((uint8_t*)&qe_target_info, sizeof(qe_target_info), (uint8_t*)&egid, sizeof(egid), &ret);
    COND2LOGERR(ret != SGX_SUCCESS, "error ocall_init_quote: %d", ret);
 
 
    COND2LOGERR(rd.size() > sizeof(sgx_report_data_t),
            "report data too long: %d, needed %d", rd.size(), sizeof(sgx_report_data_t));
    memcpy(&report_data, rd.data(), rd.size());
    
    ret = sgx_create_report(&qe_target_info, &report_data, &report);
    COND2LOGERR(SGX_SUCCESS != ret, "error sgx_create_report: %d", ret);

    ocall_get_quote(
            (uint8_t*)&state->spid,
            (uint32_t)sizeof(sgx_spid_t),
            state->sig_rl.data(),
            state->sig_rl.size(),
            state->sign_type,
            (uint8_t*)&report,
            sizeof(report),
            attestation,
            attestation_length_max,
            &attestation_length,
            &ret);
    COND2LOGERR(ret != SGX_SUCCESS, "error ocall_get_quote: %d", ret);
    COND2LOGERR(attestation_length == 0, "error get quote");

    // convert to base64 (accepted by IAS)
    b64attestation = base64_encode((const unsigned char*)attestation, attestation_length);

    return true;
    
err:
    return false;
}
