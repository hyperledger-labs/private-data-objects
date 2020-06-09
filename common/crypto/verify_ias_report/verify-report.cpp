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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "verify-report.h"
#include "ias-certificates.h"
#include "c11_support.h"

//<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
//########### INTERNAL FUNCTIONS #########################################
//########################################################################

/* EVP_DecodeBlock pads its output with \0 if the output length is not
   a multiple of 3. Check if the base64 string is padded at the end
   and adjust the output length. */
static int EVP_DecodeBlock_wrapper(unsigned char* out, int out_len, const unsigned char* in, int in_len)
{
    /* Use a temporary output buffer. We do not want to disturb the
       original output buffer with extraneous \0 bytes. */
    unsigned char buf[in_len];

    int ret = EVP_DecodeBlock(buf, in, in_len);
    COND2ERR(ret == -1);
    if (in[in_len - 1] == '=' && in[in_len - 2] == '=')
    {
        ret -= 2;
    }
    else if (in[in_len - 1] == '=')
    {
        ret -= 1;
    }

    memcpy_s(out, out_len, buf, ret);
    return ret;

err:
    return -1;
}

//########################################################################
//########### INTERNAL FUNCTIONS #########################################
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

int get_quote_from_report(const uint8_t* report, const int report_len, sgx_quote_t* quote)
{
    // Move report into \0 terminated buffer such that we can work
    // with str* functions.
    int buf_len = report_len + 1;
    char buf[buf_len];
    char* p_begin = NULL;
    char* p_end = NULL;
    int ret = -1;
    int quote_base64_len = 0;
    uint8_t* quote_bin = NULL;
    uint32_t quote_bin_len = 0;

    memcpy_s(buf, buf_len, report, report_len);
    buf[report_len] = '\0';

    const int json_string_max_len = 64;
    const char json_string[json_string_max_len] = "\"isvEnclaveQuoteBody\":\"";
    p_begin = strstr(buf, json_string);
    COND2ERR(p_begin == NULL);
    p_begin += strnlen(json_string, json_string_max_len);
    p_end = strchr(p_begin, '"');
    COND2ERR(p_end == NULL);

    quote_base64_len = p_end - p_begin;
    quote_bin = (uint8_t*)malloc(quote_base64_len);
    quote_bin_len = quote_base64_len;

    ret = EVP_DecodeBlock(quote_bin, (unsigned char*)p_begin, quote_base64_len);
    COND2ERR(ret == -1);

    quote_bin_len = ret;
    COND2ERR(quote_bin_len > sizeof(sgx_quote_t));
    memset(quote, 0, sizeof(sgx_quote_t));
    memcpy_s(quote, sizeof(sgx_quote_t), quote_bin, quote_bin_len);
    free(quote_bin);

    // success
    return 0;

err:
    return -1;
}

verify_status_t verify_ias_report_signature(const char* ias_attestation_signing_cert_pem,
                                            const char* ias_report,
                                            unsigned int ias_report_len,
                                            char* ias_signature,
                                            unsigned int ias_signature_len)
{
    X509* crt = NULL;
    int ret = -1;
    int ias_signature_decoded_len = 2048;
    unsigned char ias_signature_decoded[ias_signature_decoded_len];
    EVP_PKEY* key = NULL;
    EVP_MD_CTX* ctx = NULL;

    BIO* crt_bio = BIO_new_mem_buf((void*)ias_attestation_signing_cert_pem, -1);
    COND2ERR(crt_bio == NULL);

    crt = PEM_read_bio_X509(crt_bio, NULL, 0, NULL);
    COND2ERR(crt == NULL);

    key = X509_get_pubkey(crt);
    COND2ERR(key == NULL);

    ctx = EVP_MD_CTX_create();
    ret = EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL);
    COND2ERR(ret != 1);

    ret = EVP_VerifyUpdate(ctx, ias_report, ias_report_len);
    COND2ERR(ret != 1);

    ret = EVP_DecodeBlock_wrapper(ias_signature_decoded,
                                    ias_signature_decoded_len,
                                    (unsigned char*)ias_signature,
                                    ias_signature_len);
    COND2ERR(ret == -1);

    ret = EVP_VerifyFinal(ctx, (unsigned char*)ias_signature_decoded, ret, key);

    EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(key);
    X509_free(crt);
    BIO_free(crt_bio);

    COND2ERR(ret != 1); // 1 == correct signature

    return VERIFY_SUCCESS; /* success */

err:
    return VERIFY_FAILURE;
}

verify_status_t verify_ias_certificate_chain(const char* cert_pem)
#ifndef IAS_CA_CERT_REQUIRED
{
    return VERIFY_FAILURE; //fail (conservative approach for simulator-mode and in absence of CA certificate)
}
#else //IAS_CA_CERT_REQUIRED is defined
{
    /* Using the IAS CA certificate as a root of trust. */
    /* Checking that cert is signed by CA. */

    X509* cacrt = NULL;
    X509* crt = NULL;
    BIO* crt_bio = NULL;
    BIO* cacrt_bio = NULL;
    X509_STORE* s = NULL;
    X509_STORE_CTX* ctx = NULL;
    int rc = -1;

    COND2ERR(cert_pem == NULL);

    crt_bio = BIO_new_mem_buf((void*)cert_pem, -1);
    crt = PEM_read_bio_X509(crt_bio, NULL, 0, NULL);
    COND2ERR(crt == NULL);

    cacrt_bio = BIO_new_mem_buf((void*)ias_report_signing_ca_cert_pem, -1);
    cacrt = PEM_read_bio_X509(cacrt_bio, NULL, 0, NULL);
    // the correct CA certificate is hard-coded, so this must never fail
    assert(cacrt != NULL);

    s = X509_STORE_new();
    COND2ERR(s == NULL);
    rc = X509_STORE_add_cert(s, cacrt);
    COND2ERR(rc != 1);
    ctx = X509_STORE_CTX_new();
    COND2ERR(ctx == NULL);
    rc = X509_STORE_CTX_init(ctx, s, crt, NULL);
    COND2ERR(rc != 1);
    rc = X509_verify_cert(ctx);
    // check value after free

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(s);
    X509_free(crt);
    X509_free(cacrt);
    BIO_free(crt_bio);
    BIO_free(cacrt_bio);

    COND2ERR(rc <= 0);

    return VERIFY_SUCCESS;

err:
    return VERIFY_FAILURE;
}
#endif //IAS_CA_CERT_REQUIRED

/**
 * Check if isvEnclaveQuoteStatus is "OK"
 * (cf. https://software.intel.com/sites/default/files/managed/7e/3b/ias-api-spec.pdf,
 * pg. 24).
 *
 * @return 0 if verified successfully, 1 otherwise.
 */
verify_status_t verify_enclave_quote_status(const char* ias_report, int ias_report_len, int group_out_of_date_is_ok)
{
    // Move ias_report into \0 terminated buffer such that we can work
    // with str* functions.
    int buf_len = ias_report_len + 1;
    char buf[buf_len];
    const int status_OK_max_len = 8;
    const char status_OK[status_OK_max_len] = "OK\"";

    memcpy_s(buf, buf_len, ias_report, ias_report_len);
    buf[ias_report_len] = '\0';

    const int json_string_max_len = 64;
    const char json_string[json_string_max_len] = "\"isvEnclaveQuoteStatus\":\"";
    char* p_begin = strstr(buf, json_string);
    COND2ERR(p_begin == NULL);
    p_begin += strnlen(json_string, json_string_max_len);

    if (0 == strncmp(p_begin, status_OK, strnlen(status_OK, status_OK_max_len)))
    {
        return VERIFY_SUCCESS;
    }

    if(group_out_of_date_is_ok)
    {
        const int status_outdated_max_len = 64;
        const char status_outdated[status_outdated_max_len] = "GROUP_OUT_OF_DATE\"";
        if (0 == strncmp(p_begin, status_outdated, strnlen(status_outdated, status_outdated_max_len)))
        {
            return VERIFY_SUCCESS;
        }
    }

err:
    //quote not ok
    return VERIFY_FAILURE;
}
