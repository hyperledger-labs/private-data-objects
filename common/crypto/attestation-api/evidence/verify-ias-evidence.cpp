/*
 * Copyright 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "error.h"
#include "logging.h"
#include "base64/base64.h"
#include "crypto/verify_ias_report/verify-report.h"
#include "types/types.h"
#include "crypto/sha256.h"
#include "attestation_tags.h"

// < JSON include
#define JSON_HAS_CPP_11
#define JSON_NO_IO 1
#include <errno.h>
#include "nlohmann/json.hpp"
using json = nlohmann::json;
// JSON include >

static bool unwrap_ias_evidence(const std::string& evidence_str,
    std::string& ias_signature,
    std::string& ias_certificates,
    std::string& ias_report,
    std::string& untrusted_time_str)
{
    json root;
    bool ret;

    CATCH(ret, root = json::parse(evidence_str));
    COND2LOGERR(!ret, "invalid ias evidence json");

    CATCH(ret, ias_signature = root[IAS_SIGNATURE_TAG].template get<std::string>());
    COND2LOGERR(!ret, "invalid ias_signature field");

    CATCH(ret, ias_certificates = root[IAS_CERTIFICATES_TAG].template get<std::string>());
    COND2LOGERR(!ret, "invalid ias_certificates field");

    CATCH(ret, ias_report = root[IAS_REPORT_TAG].template get<std::string>());
    COND2LOGERR(!ret, "invalid ias_report field");

    CATCH(ret, untrusted_time_str = root[UNTRUSTED_TIME_T_TAG].template get<std::string>());
    COND2LOGERR(!ret, "invalid untrusted time field");

    return true;

err:
    LOG_DEBUG("ias evidence: %s\n", evidence_str.c_str());
    return false;
}

static void replace_all_substrings(
    std::string& s, const std::string& substring, const std::string& replace_with)
{
    size_t pos = 0;
    while (1)
    {
        pos = s.find(substring, pos);
        if (pos == std::string::npos)
            break;

        s.replace(pos, substring.length(), replace_with);
    }
}

static void url_decode_ias_certificate(std::string& s)
{
    replace_all_substrings(s, "%20", " ");
    replace_all_substrings(s, "%0A", "\n");
    replace_all_substrings(s, "%2B", "+");
    replace_all_substrings(s, "%3D", "=");
    replace_all_substrings(s, "%2F", "/");
}

static bool split_certificates(
    std::string& ias_certificates, std::vector<std::string>& ias_certificate_vector)
{
    // ias certificates should have 2 certificates "-----BEGIN CERTIFICATE----- [...] -----END
    // CERTIFICATE-----\n"
    std::string cert_start("-----BEGIN CERTIFICATE-----");
    std::string cert_end("-----END CERTIFICATE-----\n");
    size_t cur = 0, start = 0, end = 0;

    ias_certificate_vector.clear();

    url_decode_ias_certificate(ias_certificates);

    while (1)
    {
        start = ias_certificates.find(cert_start, cur);
        if (start == std::string::npos)
        {
            break;
        }

        end = ias_certificates.find(cert_end, cur);
        if (end == std::string::npos)
        {
            break;
        }
        end += cert_end.length();

        ias_certificate_vector.push_back(ias_certificates.substr(start, end));
        cur = end;
    }

    COND2LOGERR(ias_certificate_vector.size() != 2, "unexpected number of IAS certificates");

    return true;

err:
    return false;
}

static bool extract_hex_from_report(
    const std::string& ias_report, size_t offset, size_t size, std::string& hex)
{
    std::string b64quote;
    ByteArray bin_quote;
    ByteArray ba;
    bool ret = false;
    json root;

    CATCH(ret, root = json::parse(ias_report));
    COND2LOGERR(!ret, "invalid ias_report json");

    CATCH(ret, b64quote = root["isvEnclaveQuoteBody"].template get<std::string>());
    COND2LOGERR(!ret, "invalid isvEnclaveQuoteBody field");

    bin_quote = Base64EncodedStringToByteArray(b64quote);
    COND2LOGERR(bin_quote.size() != offsetof(sgx_quote_t, signature_len), "unexpected quote size");
    ba = ByteArray(bin_quote.data() + offset, bin_quote.data() + offset + size);
    hex = ByteArrayToHexEncodedString(ba);

    return true;

err:
    return false;
}

bool verify_ias_evidence(
    ByteArray& evidence, ByteArray& expected_statement, ByteArray& expected_code_id)
{
    time_t untrusted_time = 0;
    std::string evidence_str((char*)evidence.data(), evidence.size());
    std::string expected_hex_id((char*)expected_code_id.data(), expected_code_id.size());

    std::string ias_signature, ias_certificates, ias_report, untrusted_time_str;
    std::vector<std::string> ias_certificate_vector;

    // get evidence data
    COND2ERR(
        false == unwrap_ias_evidence(evidence_str, ias_signature, ias_certificates, ias_report, untrusted_time_str));

    // split certs
    COND2ERR(false == split_certificates(ias_certificates, ias_certificate_vector));

    {
        //get time
        unsigned long long timeull = std::stoull(untrusted_time_str);
        COND2LOGERR(sizeof(timeull) != sizeof(time_t), "error: ull and time_t have different sizes" );
        untrusted_time = *((time_t*)(&timeull));
        LOG_DEBUG("untrusted time: %llu\n", timeull);
    }

    {
        // verify report status
        const unsigned int flags = QSF_ACCEPT_GROUP_OUT_OF_DATE | QSF_ACCEPT_CONFIGURATION_NEEDED |
                                   QSF_ACCEPT_SW_HARDENING_NEEDED |
                                   QSF_ACCEPT_CONFIGURATION_AND_SW_HARDENING_NEEDED;
        COND2LOGERR(VERIFY_SUCCESS !=
                        verify_enclave_quote_status(ias_report.c_str(), ias_report.length(), flags),
            "invalid quote status");
    }

    {
        // check root cert
        const int root_certificate_index = 1;
        verify_status_t v;
        bool ret;
        CATCH(ret, v = verify_ias_certificate_chain(ias_certificate_vector[root_certificate_index].c_str(), untrusted_time));
        COND2LOGERR(!ret, "verify root cert exception");
        COND2LOGERR(VERIFY_SUCCESS != v, "invalid root certificate");
    }

    {
        // check signing cert
        const int signing_certificate_index = 0;
        verify_status_t v;
        bool ret;
        CATCH(ret, v = verify_ias_certificate_chain(ias_certificate_vector[signing_certificate_index].c_str(), untrusted_time));
        COND2LOGERR(!ret, "verify intermediate cert exception");
        COND2LOGERR(VERIFY_SUCCESS != v, "invalid intermediate certificate");

        // check signature
        COND2LOGERR(
                VERIFY_SUCCESS != verify_ias_report_signature(
                                          ias_certificate_vector[signing_certificate_index].c_str(),
                                          ias_report.c_str(), ias_report.length(),
                                          (char*)ias_signature.c_str(), ias_signature.length()),
                "invalid report signature");
    }

    {
        // check code id
        std::string hex_id;
        COND2ERR(false ==
                 extract_hex_from_report(ias_report,
                     offsetof(sgx_quote_t, report_body) + offsetof(sgx_report_body_t, mr_enclave),
                     sizeof(sgx_measurement_t), hex_id));
        LOG_DEBUG("code id comparision: found '%s' (len=%ld) / expected '%s' (len=%ld)",
            hex_id.c_str(), hex_id.length(), expected_hex_id.c_str(), expected_hex_id.length());
        COND2LOGERR(0 != hex_id.compare(expected_hex_id), "expected code id mismatch");
    }

    {
        // check report data
        std::string hex_report_data, expected_hex_report_data_str;
        ByteArray hash;
        COND2ERR(false ==
                 extract_hex_from_report(ias_report,
                     offsetof(sgx_quote_t, report_body) + offsetof(sgx_report_body_t, report_data),
                     sizeof(sgx_report_data_t), hex_report_data));
        COND2ERR(false == SHA256(expected_statement, hash));
        expected_hex_report_data_str = ByteArrayToHexEncodedString(hash);
        expected_hex_report_data_str.append(expected_hex_report_data_str.length(), '0');
        COND2LOGERR(0 != hex_report_data.compare(expected_hex_report_data_str),
            "expected statement mismatch");
    }

    // TODO: check attributes of attestation (e.g., DEBUG flag disabled in release mode)

    return true;

err:
    return false;
}

