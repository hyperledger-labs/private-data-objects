/*
 * Copyright 2024 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <algorithm>
#include <string>
#include <cstring>
#include "types/types.h"
#include "base64/base64.h"
#include "sgx_ql_lib_common.h"
#include "sgx_dcap_quoteverify.h"

uint8_t* serialize_collateral(sgx_ql_qve_collateral_t* c)
{
        uint32_t collateral_size = sizeof(sgx_ql_qve_collateral_t) + c->pck_crl_issuer_chain_size + c->root_ca_crl_size + c->pck_crl_size + c->tcb_info_issuer_chain_size + c->tcb_info_size + c->qe_identity_issuer_chain_size + c->qe_identity_size;
        fprintf(stderr, "calculated collateral size: %d\n", collateral_size);

        uint8_t* p = (uint8_t*)malloc(collateral_size);
        if(p == NULL) return NULL;
        memset(p, '\0', collateral_size);

        // NOTICE / WARNING: here we copy the entire data structure with "meaningless" pointers
        // pointers will have to be adjusted at deserialization time
        memcpy(p, (uint8_t*)c, sizeof(sgx_ql_qve_collateral_t));
        memcpy(p+sizeof(sgx_ql_qve_collateral_t), c->pck_crl_issuer_chain, c->pck_crl_issuer_chain_size);
        memcpy(p+sizeof(sgx_ql_qve_collateral_t)+c->pck_crl_issuer_chain_size, c->root_ca_crl, c->root_ca_crl_size);
        memcpy(p+sizeof(sgx_ql_qve_collateral_t)+c->pck_crl_issuer_chain_size+c->root_ca_crl_size, c->pck_crl, c->pck_crl_size);
        memcpy(p+sizeof(sgx_ql_qve_collateral_t)+c->pck_crl_issuer_chain_size+c->root_ca_crl_size+c->pck_crl_size, c->tcb_info_issuer_chain, c->tcb_info_issuer_chain_size);
        memcpy(p+sizeof(sgx_ql_qve_collateral_t)+c->pck_crl_issuer_chain_size+c->root_ca_crl_size+c->pck_crl_size+c->tcb_info_issuer_chain_size, c->tcb_info, c->tcb_info_size);
        memcpy(p+sizeof(sgx_ql_qve_collateral_t)+c->pck_crl_issuer_chain_size+c->root_ca_crl_size+c->pck_crl_size+c->tcb_info_issuer_chain_size+c->tcb_info_size, c->qe_identity_issuer_chain, c->qe_identity_issuer_chain_size);
        memcpy(p+sizeof(sgx_ql_qve_collateral_t)+c->pck_crl_issuer_chain_size+c->root_ca_crl_size+c->pck_crl_size+c->tcb_info_issuer_chain_size+c->tcb_info_size+c->qe_identity_issuer_chain_size, c->qe_identity, c->qe_identity_size);

        return p;
}


int main(int argc, char** argv)
{
    if(argc != 2)
    {
        printf("Usage: %s <b64attestation string>\n", argv[0]);
    	return -1;
    }

    std::string s = base64_decode(argv[1]);
    ByteArray attestation;
    std::transform(s.begin(), s.end(), std::back_inserter(attestation),
		    [](unsigned char c) -> char { return (uint8_t)c; });


    uint8_t* p_collateral=NULL;
    uint32_t collateral_size=0;
    quote3_error_t ret = tee_qv_get_collateral(attestation.data(), attestation.size(), &p_collateral, &collateral_size);
    if(ret != SGX_QL_SUCCESS)
    {
        printf("error getting collateral: %x\n", ret);
        return -1;
    }

    uint8_t* serialized_collateral = serialize_collateral((sgx_ql_qve_collateral_t*)p_collateral);
    if(serialized_collateral == NULL)
    {
       printf("error allocating collateral");
       return -1;
    }
    std::string b64collateral = base64_encode((const unsigned char*)serialized_collateral, collateral_size);
    puts(b64collateral.c_str());

    fprintf(stderr, "[DEBUG] collateral major version %hu minor version %hu\n",
            ((sgx_ql_qve_collateral_t*)p_collateral)->major_version,
            ((sgx_ql_qve_collateral_t*)p_collateral)->minor_version);
    fprintf(stderr, "[DEBUG] collateral size: %d\n", collateral_size);
    fprintf(stderr, "[DEBUG] b64collateral size: %ld\n", b64collateral.length());

    ret = tee_qv_free_collateral(p_collateral);
    if(ret != SGX_QL_SUCCESS)
    {
        printf("error freeing collateral: %x\n", ret);
        return -1;
    }
    free(serialized_collateral);

    return 0;
}
