/* Copyright 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef VERIFY_REPORT_H
#define VERIFY_REPORT_H

#include <sgx_quote.h>

extern const char* const ias_report_signing_ca_cert_pem;

typedef enum
{
    VERIFY_SUCCESS,
    VERIFY_FAILURE
} verify_status_t;

typedef enum
{
    QS_INVALID,
    QS_OK,
    QS_GROUP_OUT_OF_DATE,
    QS_CONFIGURATION_NEEDED,
    QS_SW_HARDENING_NEEDED,
    QS_CONFIGURATION_AND_SW_HARDENING_NEEDED,
    QS_NUMBER
} quote_status_e;

#define QSF_ACCEPT_GROUP_OUT_OF_DATE (1 << QS_GROUP_OUT_OF_DATE)
#define QSF_ACCEPT_CONFIGURATION_NEEDED (1 << QS_CONFIGURATION_NEEDED)
#define QSF_ACCEPT_SW_HARDENING_NEEDED (1 << QS_SW_HARDENING_NEEDED)
#define QSF_ACCEPT_CONFIGURATION_AND_SW_HARDENING_NEEDED \
    (1 << QS_CONFIGURATION_AND_SW_HARDENING_NEEDED)
#define QSF_ACCEPT_ALL UINT_MAX
#define QSF_REJECT_ALL (0)

#ifdef __cplusplus
extern "C" {
#endif

int get_quote_from_report(const uint8_t* report, const int report_len, sgx_quote_t* quote);
verify_status_t verify_enclave_quote_status(const char* ias_report,
                                            unsigned int ias_report_len,
                                            unsigned int quote_status_flags);
verify_status_t verify_ias_certificate_chain(const char* cert_pem);
verify_status_t verify_ias_report_signature(const char* const ias_attestation_signing_cert_pem,
                                            const char* ias_report,
                                            const unsigned int ias_report_len,
                                            const char* ias_signature,
                                            const unsigned int ias_signature_len);

quote_status_e get_quote_status(const char* ias_report, unsigned int ias_report_len);
#ifdef __cplusplus
}
#endif

#define COND2ERR(b)   \
    do                \
    {                 \
        if (b)        \
        {             \
            goto err; \
        }             \
    } while (0)

#endif
