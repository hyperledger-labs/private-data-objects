/*
 * Copyright 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sgx_uae_epid.h>
#include "error.h"
#include "logging.h"
#include "sgx_quote.h"
#include "sgx_dcap_ql_wrapper.h"

void ocall_init_quote(uint8_t* target, uint32_t target_len, uint8_t* egid, uint32_t egid_len, uint32_t* sgxret)
{
    COND2LOGERR(target == NULL, "null sgx target info");

    if(egid != NULL) //this means: EPID
    {
        int ret = sgx_init_quote((sgx_target_info_t*)target, (sgx_epid_group_id_t*)egid);
        *sgxret = ret;
        COND2LOGERR(ret != SGX_SUCCESS, "error sgx_init_quote: %x", ret);
    }
    else // no egid means: DCAP
    {
        quote3_error_t qe3_ret;
        qe3_ret = sgx_qe_get_target_info((sgx_target_info_t*)target);
        *sgxret = qe3_ret;
        COND2LOGERR(qe3_ret != SGX_QL_SUCCESS, "error sgx_qe_get_target_info: %x", qe3_ret);
    }
    return;

err:
    ; // nothing to do
}

void ocall_get_quote(uint8_t* spid,
    uint32_t spid_len,
    uint8_t* sig_rl,
    uint32_t sig_rl_len,
    uint32_t sign_type,
    uint8_t* report,
    uint32_t report_len,
    uint8_t* quote,
    uint32_t max_quote_len,
    uint32_t* actual_quote_len,
    uint32_t* sgxret)
{
    if(spid != NULL) // this means: EPID
    {
        int ret;
        uint32_t required_quote_size = 0;
        ret = sgx_calc_quote_size(sig_rl, sig_rl_len, &required_quote_size);
        *sgxret = ret;
        COND2LOGERR(ret != SGX_SUCCESS, "error sgx_calc_quote_size: %x", ret);
        COND2LOGERR(
                required_quote_size > max_quote_len,
                "error not enough buffer for quote: required %d max %d",
                required_quote_size, max_quote_len);
    
        ret = sgx_get_quote(
                (const sgx_report_t*)report,
                (sgx_quote_sign_type_t)sign_type,
                (const sgx_spid_t*)spid,  // spid
                NULL,                     // nonce
                sig_rl,                   // sig_rl
                sig_rl_len,               // sig_rl_size
                NULL,                     // p_qe_report
                (sgx_quote_t*)quote, required_quote_size);
        *sgxret = ret;
        COND2LOGERR(ret != SGX_SUCCESS, "error sgx_get_quote: %x", ret);
        *actual_quote_len = required_quote_size;
    }
    else // this means DCAP
    {
        quote3_error_t qe3_ret;
        uint32_t required_quote_size = 0;
        qe3_ret = sgx_qe_get_quote_size(&required_quote_size);
        *sgxret = qe3_ret;
        COND2LOGERR(qe3_ret != SGX_QL_SUCCESS, "error sgx_qe_get_quote_size: %x", qe3_ret);
        COND2LOGERR(
                required_quote_size > max_quote_len,
                "error not enough buffer for quote: required %d max %d",
                required_quote_size, max_quote_len);

        qe3_ret = sgx_qe_get_quote(
                (const sgx_report_t*)report,
                required_quote_size,
                quote);
        *sgxret = qe3_ret;
        COND2LOGERR(qe3_ret != SGX_QL_SUCCESS, "error sgx_qe_get_quote: %x", qe3_ret);
        *actual_quote_len = required_quote_size;
    }    

    return;

err:
    // if anything wrong, no quote
    *actual_quote_len = 0;
}
