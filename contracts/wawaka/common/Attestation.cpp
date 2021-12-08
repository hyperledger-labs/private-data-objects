/* Copyright 2019 Intel Corporation
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

//#include <malloc.h>
#include <algorithm>
#include <stdint.h>
#include <string>

#include "Attestation.h"
#include "Util.h"
#include "Value.h"
#include "WasmExtensions.h"

/* ----------------------------------------------------------------- *
 * NAME: ww::attestation::verify_sgx_report
 * ----------------------------------------------------------------- */
bool ww::attestation::verify_sgx_report(
    const std::string& certificate,
    const std::string& report,
    const std::string& signature)
{
    return ::verify_sgx_report(
        certificate.c_str(), certificate.length(),
        report.c_str(), report.length(),
        signature.c_str(), signature.length());
}

/* ----------------------------------------------------------------- *
 * NAME: ww::attestation::parse_sgx_report
 * ----------------------------------------------------------------- */
bool ww::attestation::parse_sgx_report(
    const std::string& report,
    ww::value::Object& parsed)
{
    std::string result;
    char* data_pointer = NULL;
    size_t data_size = 0;

    bool status = ::parse_sgx_report(
        report.c_str(), report.length(),
        &data_pointer, &data_size);

    if (! status)
    {
        CONTRACT_SAFE_LOG(3, "failed to parse sgx report");
        return false;
    }

    status = parsed.deserialize(data_pointer);
    if (! status)
    {
        CONTRACT_SAFE_LOG(3, "unexpected error: parse_sgx_report returned invalid");
        return false;
    }

    return true;
}
