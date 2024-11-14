/*
 * Copyright 2024 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstdio>
#include <algorithm>
#include <vector>
#include <string>
#include <array>
#include "types/types.h"
#include "types/hex_string.h"
#include "error.h"
#include "logging.h"
#include "crypto/sha256.h"
#include "crypto/verify_dcap_direct/get_dcap_certificate.h"
#include "base64/base64.h"
#include "attestation_tags.h"

#include "sgx_quote_3.h"
#include "SgxEcdsaAttestation/QuoteVerification.h"
#include "QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h"
#include "CertVerification/CertificateChain.h"

// < JSON include
#define JSON_HAS_CPP_11
#define JSON_NO_IO 1
#include <errno.h>
#include "nlohmann/json.hpp"
using json = nlohmann::json;
// JSON include >

#include "PckParser/CrlStore.h"
#include "../../AttestationCommons/include/Utils/TimeUtils.h"

/********************************************************
 * Internal function to modify "in-place" the collateral
 * data structure, so that pointers point to buffers
 * appended to the structure
 *******************************************************/
void deserialize_collateral(uint8_t* p)
{
    sgx_ql_qve_collateral_t* c = (sgx_ql_qve_collateral_t*)p;

    c->pck_crl_issuer_chain     = (char*)p + sizeof(sgx_ql_qve_collateral_t);
    c->root_ca_crl              = (char*)c->pck_crl_issuer_chain + c->pck_crl_issuer_chain_size;
    c->pck_crl                  = (char*)c->root_ca_crl + c->root_ca_crl_size;
    c->tcb_info_issuer_chain    = (char*)c->pck_crl + c->pck_crl_size;
    c->tcb_info                 = (char*)c->tcb_info_issuer_chain + c->tcb_info_issuer_chain_size;
    c->qe_identity_issuer_chain = (char*)c->tcb_info + c->tcb_info_size;
    c->qe_identity              = (char*)c->qe_identity_issuer_chain + c->qe_identity_issuer_chain_size;
}


bool verify_dcap_direct_evidence(ByteArray& evidence, ByteArray& expected_statement, ByteArray& expected_code_id)
{
    ByteArray quote;
    ByteArray certification_data;
    uint32_t certification_data_size;
    uint16_t certification_data_type;
    ByteArray collateral;
    time_t untrusted_time;
    bool b;
    Status qvl_status;
    sgx_ql_qve_collateral_t* p_collateral;

    {
        //parse evidence
        json root;
        std::string evidence_str((char*)evidence.data(), evidence.size());
        LOG_DEBUG("evidence: %s", evidence_str.c_str());
        CATCH(b, root = json::parse(evidence_str));
        COND2LOGERR(!b, "bad dcap evidence json");

        //get attestation
        std::string b64attestation_str;
        std::string attestation_str;
        CATCH(b, b64attestation_str = root[ATTESTATION_TAG].template get<std::string>());
        COND2LOGERR(!b, "no attestation for dcap direct verification");
        attestation_str = base64_decode(b64attestation_str);
        std::transform(attestation_str.begin(), attestation_str.end(),
                std::back_inserter(quote),
                [](unsigned char c) -> char { return (uint8_t)c; });

        //get collateral
        std::string b64collateral_str;
        std::string collateral_str;
        CATCH(b, b64collateral_str = root[COLLATERAL_TAG].template get<std::string>());
        COND2LOGERR(!b, "no collateral for dcap direct verification");
        collateral_str = base64_decode(b64collateral_str);
        std::transform(collateral_str.begin(), collateral_str.end(),
                std::back_inserter(collateral),
                [](unsigned char c) -> char { return (uint8_t)c; });
        //adjust the collateral structure pointers
        deserialize_collateral(collateral.data());
        p_collateral = (sgx_ql_qve_collateral_t*)collateral.data();
        LOG_DEBUG("collateral version: %u\n", p_collateral->version);
        LOG_DEBUG("collateral major %hu minor %hu\n",
                p_collateral->major_version, p_collateral->minor_version);
        LOG_DEBUG("collateral size %ld\n", collateral.size());

        //get untrusted time for verification
        unsigned long long timeull;
        std::string time_str;
        CATCH(b, time_str = root[UNTRUSTED_TIME_T_TAG].template get<std::string>());
        COND2LOGERR(!b, "no untrusted-time for dcap direct verification");
        timeull = std::stoull(time_str);
        COND2LOGERR(sizeof(timeull) != sizeof(time_t), "error: ull and time_t have different sizes" );
        untrusted_time = *((time_t*)(&timeull));
        LOG_DEBUG("untrusted time str: %s\n", time_str.c_str());
        LOG_DEBUG("untrusted time ull: %llu\n", timeull);
    }

    //verify quote
    {
        qvl_status = sgxAttestationGetQECertificationDataSize(quote.data(), quote.size(), &certification_data_size);
        COND2LOGERR(qvl_status != STATUS_OK,
                "error certification data size: %x", qvl_status);

        certification_data.resize(certification_data_size);

        qvl_status = sgxAttestationGetQECertificationData(
                quote.data(), quote.size(),
                certification_data.size(), certification_data.data(),
                &certification_data_type);
        COND2LOGERR(qvl_status != STATUS_OK,
                "error certification data: %x", qvl_status);

        std::string dcap_ca_certificate;
        get_dcap_certificate(dcap_ca_certificate);
        std::string certification_data_str(certification_data.begin(), certification_data.end());
        std::string root_ca_crl_str;
        std::string pck_crl_str;

        // we check up to the last but one char (because, if hex form, it could be a space)
        if(IsHex((const uint8_t*)p_collateral->root_ca_crl, p_collateral->root_ca_crl_size-1))
        {
            root_ca_crl_str =
                std::string(p_collateral->root_ca_crl, p_collateral->root_ca_crl_size);
        }
        else
        {
            char c = p_collateral->root_ca_crl[p_collateral->root_ca_crl_size-1];
            uint32_t size = p_collateral->root_ca_crl_size;
            size -= (std::isspace(c) ? 1 : 0);
            root_ca_crl_str = BinaryToHexString((const uint8_t*)p_collateral->root_ca_crl, size);
            if(p_collateral->major_version == 3 && p_collateral->minor_version == 0)
                LOG_WARNING("WARNING: root ca crl is not hex but collateral version is 3.0 (so it should be)\n");
        }

        // we check up to the last but one char (because, if hex form, it could be a space)
        if(IsHex((const uint8_t*)p_collateral->pck_crl, p_collateral->pck_crl_size-1))
        {
            pck_crl_str =
                std::string(p_collateral->pck_crl, p_collateral->pck_crl_size);
        }
        else
        {
            char c = p_collateral->pck_crl[p_collateral->pck_crl_size-1];
            uint32_t size = p_collateral->pck_crl_size;
            size -= (std::isspace(c) ? 1 : 0);
            pck_crl_str = BinaryToHexString((const uint8_t*)p_collateral->pck_crl, p_collateral->pck_crl_size);
            if(p_collateral->major_version == 3 && p_collateral->minor_version == 0)
                LOG_WARNING("WARNING: pck crl is not hex but collateral version is 3.0 (so it should be)\n");
        }

        const std::array<const char*, 2> crls{{
            root_ca_crl_str.c_str(), pck_crl_str.c_str()}};

        LOG_DEBUG("dcap_ca_certificate: %s\n", dcap_ca_certificate.c_str());
        LOG_DEBUG("Certification data type: %hu\n", certification_data_type);
        LOG_DEBUG("Certification data: %s\n", certification_data_str.c_str());
        LOG_DEBUG("root_ca_crl_str (%ld): %s\n", root_ca_crl_str.length(), root_ca_crl_str.c_str());
        LOG_DEBUG("pck_crl_str(%ld): %s\n", pck_crl_str.length(), pck_crl_str.c_str());

        {
            // debug CRLS
            time_t currentTime = intel::sgx::dcap::getCurrentTime((const time_t*)&untrusted_time);
            intel::sgx::dcap::pckparser::CrlStore rootCaCrl;
            intel::sgx::dcap::pckparser::CrlStore intermediateCrl;
            COND2LOGERR(!rootCaCrl.parse(crls[0]), "error parsing rootcacrsl");
            COND2LOGERR(!intermediateCrl.parse(crls[1]), "error parsing intermediateCrl");
            LOG_DEBUG("rootCaCrl.getValidity().notBeforeTime: %llu\n", *((unsigned long long*)(&(rootCaCrl.getValidity().notBeforeTime))));
            LOG_DEBUG("rootCaCrl.getValidity().notAfterTime: %llu\n", *((unsigned long long*)(&(rootCaCrl.getValidity().notAfterTime))));
            LOG_DEBUG("currentTime: %llu\n", *((unsigned long long*)&currentTime));

            LOG_DEBUG("intermediateCrl.getValidity().notBeforeTime: %llu\n", *((unsigned long long*)(&(intermediateCrl.getValidity().notBeforeTime))));
            LOG_DEBUG("intermediateCrl.getValidity().notAfterTime: %llu\n", *((unsigned long long*)(&(intermediateCrl.getValidity().notAfterTime))));
        }

        qvl_status = sgxAttestationVerifyPCKCertificate(
                certification_data_str.c_str(),
                crls.data(),
                dcap_ca_certificate.c_str(),
                &untrusted_time);
        COND2LOGERR(qvl_status != STATUS_OK,
                "error PCK certificate verification: %x", qvl_status);

        qvl_status = sgxAttestationVerifyTCBInfo(
                p_collateral->tcb_info,
                p_collateral->tcb_info_issuer_chain,
                crls[0],
                dcap_ca_certificate.c_str(),
                &untrusted_time);
        COND2LOGERR(qvl_status != STATUS_OK,
                "error TCB info verification: %x", qvl_status);

        qvl_status = sgxAttestationVerifyEnclaveIdentity(
                p_collateral->qe_identity,
                p_collateral->qe_identity_issuer_chain,
                crls[0],
                dcap_ca_certificate.c_str(),
                &untrusted_time);
        COND2LOGERR(qvl_status != STATUS_OK,
                "error QE identity verification: %x", qvl_status);

        intel::sgx::dcap::CertificateChain chain;
        qvl_status = chain.parse((const char*)certification_data.data());
        COND2LOGERR(qvl_status != STATUS_OK,
                "error parsing certification data: %x", qvl_status);

        qvl_status = sgxAttestationVerifyQuote(
                quote.data(),
                quote.size(),
                chain.getPckCert()->getPem().c_str(),
                crls[1],
                p_collateral->tcb_info,
                p_collateral->qe_identity);
        COND2LOGERR(
                //these checks are mostly the verification policy
		//TODO: define and implement better strategy for verification
                qvl_status != STATUS_OK &&
                qvl_status != STATUS_TCB_OUT_OF_DATE,
                "error quote verification: %x", qvl_status);
    }

    // verify code id and statement
    {
        //prepare code id
        sgx_quote3_t* q = (sgx_quote3_t*)quote.data();
        std::string code_id = BinaryToHexString((const uint8_t*)&q->report_body.mr_enclave, sizeof(sgx_measurement_t));
        std::string expected_hex_id((char*)expected_code_id.data(), expected_code_id.size());
        LOG_DEBUG("quote version: %hu\n", q->header.version);
        LOG_DEBUG("Code id in quote: %s\n", code_id.c_str());
        LOG_DEBUG("Expected code id: %s\n", expected_hex_id.c_str());

        //prepare statements
        std::string hex_report_data = BinaryToHexString((const uint8_t*)&q->report_body.report_data, sizeof(sgx_report_data_t));
        ByteArray hash;
        COND2ERR(false == SHA256(expected_statement, hash));
        std::string expected_hex_report_data_str = ByteArrayToHexEncodedString(hash);
        expected_hex_report_data_str.append(expected_hex_report_data_str.length(), '0');
        LOG_DEBUG("report data: %s\n", hex_report_data.c_str());
        LOG_DEBUG("expected report data: %s\n", expected_hex_report_data_str.c_str());

        // code check
        COND2LOGERR(0 != code_id.compare(expected_hex_id), "expected code id mismatch");

        //statement check
        COND2LOGERR(0 != hex_report_data.compare(expected_hex_report_data_str), "expected statement mismatch");
    }

    return true;

err:
    return false;
}
