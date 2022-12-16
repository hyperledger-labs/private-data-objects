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

#include "enclave_u.h"

#include <linux/limits.h>

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <unistd.h>
#include <pthread.h>

#include <sgx_uae_service.h>
#include "sgx_support.h"

#include "log.h"

#include "error.h"
#include "hex_string.h"
#include "pdo_error.h"
#include "types.h"
#include "zero.h"

#include "enclave.h"

#include "sgx_dcap_ql_wrapper.h"

std::vector<pdo::enclave_api::Enclave> g_Enclave;

namespace pdo {
    namespace error {
        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        sgx_status_t ConvertErrorStatus(
            sgx_status_t ret,
            pdo_err_t pdoRet)
        {
            // If the SGX code is successs and the PDO error code is
            // "busy", then convert to appropriate value.
            if ((SGX_SUCCESS == ret) &&
                (PDO_ERR_SYSTEM_BUSY == pdoRet)) {
                return SGX_ERROR_DEVICE_BUSY;
            }

            return ret;
        } // ConvertErrorStatus
    }

    namespace enclave_api {

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        // XX External interface                                     XX
        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        Enclave::Enclave() :
            enclaveId(0),
            sealedSignupDataSize(0),
            attestationType("")
        {
        } // Enclave::Enclave

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        Enclave::~Enclave()
        {
            try {
                this->Unload();
            } catch (error::Error& e) {
                pdo::logger::LogV(
                    PDO_LOG_ERROR,
                    "Error unloading pdo enclave: %04X -- %s",
                    e.error_code(),
                    e.what());
            } catch (...) {
                pdo::logger::Log(
                    PDO_LOG_ERROR,
                    "Unknown error unloading pdo enclave");
            }
        } // Enclave::~Enclave

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::Load(
            const std::string& inEnclaveFilePath
            )
        {
            pdo::error::ThrowIf<pdo::error::ValueError>(
                inEnclaveFilePath.empty() ||
                inEnclaveFilePath.length() > PATH_MAX,
                "Invalid enclave path.");

            this->Unload();
            this->enclaveFilePath = inEnclaveFilePath;
            this->LoadEnclave();
        } // Enclave::Load

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::Unload()
        {
            if (this->enclaveId) {
                // no power or busy retries here....
                // we don't want to reinitialize just to shutdown.
                sgx_destroy_enclave(this->enclaveId);
                this->enclaveId = 0;
            }
        } // Enclave::Unload

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        static void* Worker(void* arg)
        {
            Enclave* enc = static_cast<Enclave* >(arg);

            pdo::logger::LogV(PDO_LOG_INFO, "Enclave::Worker[%ld] %ld", (long)enc->GetEnclaveId(), enc->GetThreadId());

            sgx_status_t ret;
            pdo_err_t pdoError = PDO_SUCCESS;

            ret = enc->CallSgx([enc, &pdoError] () {
                    sgx_status_t ret =
                    ecall_CreateContractWorker(
                        enc->GetEnclaveId(),
                        &pdoError,
                        enc->GetThreadId());
                    return error::ConvertErrorStatus(ret, pdoError);
                });
            pdo::error::ThrowSgxError(
                ret,
                "Enclave call to ecall_CreateContractWorker failed");
            enc->ThrowPDOError(pdoError);

            return NULL;

        } // Enclave::Worker

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::StartWorker()
        {
            try {
                pthread_t thread;
                int err = pthread_create(&thread, NULL, Worker, this);
                if (err)
                    throw error::Error((pdo_err_t)err, "Enclave::StartWorker(): pthread_create failed");

                this->threadId = (long)thread;

            } catch (error::Error& e) {
                pdo::logger::LogV(
                    PDO_LOG_ERROR,
                    "Error starting pdo enclave worker thread: %04X -- %s",
                    e.error_code(),
                    e.what());
            } catch (...) {
                pdo::logger::Log(
                    PDO_LOG_ERROR,
                    "Unknown error starting pdo enclave worker");
                throw;
            }
        }// Enclave::StartWorker

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::ShutdownWorker()
        {
            pdo::logger::LogV(PDO_LOG_INFO, "Enclave::ShutdownWorker[%ld]", (long)this->GetEnclaveId());

            sgx_status_t ret;
            pdo_err_t pdoError = PDO_SUCCESS;

            ret = this->CallSgx([this, &pdoError] () {
                    sgx_status_t ret =
                    ecall_ShutdownContractWorker(
                        this->GetEnclaveId(),
                        &pdoError);
                    return error::ConvertErrorStatus(ret, pdoError);
                });
            pdo::error::ThrowSgxError(
                ret,
                "Enclave call to ecall_ShutdownContractWorker failed");
            this->ThrowPDOError(pdoError);

            // wait for the worker thread to shutdown before continuing
            pthread_join(this->threadId, NULL);
        }// Enclave::ShutdownWorker

        size_t Enclave::GetQuoteSize() const
        {
            uint32_t quoteSize;

            if(this->attestationType == "dcap")
            {
                quote3_error_t qe3_ret;
                qe3_ret = sgx_qe_get_quote_size(&quoteSize);
                pdo::error::ThrowIf<pdo::error::RuntimeError>(
                        SGX_QL_SUCCESS != qe3_ret,
                        "Failed to get quote size");
            }
            else
            {
                uint32_t rlSize;
                const uint8_t* prl = this->GetSignatureRevocationList(&rlSize);
                pdo::error::ThrowSgxError(sgx_calc_quote_size(prl, rlSize, &quoteSize));
            }

            return quoteSize;
        }

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::GetEpidGroup(
            sgx_epid_group_id_t* outEpidGroup
            )
        {
            pdo::error::ThrowIf<pdo::error::RuntimeError>(
                    this->attestationType.empty(),
                    "Error: epid group not available, attestation type not set");

            //copy epid group into output parameter
            memcpy_s(
                outEpidGroup,
                sizeof(sgx_epid_group_id_t),
                &this->epidGroupId,
                sizeof(sgx_epid_group_id_t));
        } // Enclave::GetEpidGroup

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::GetTargetInfo(
             sgx_target_info_t* outTagetInfo
             )
        {
            pdo::error::ThrowIf<pdo::error::RuntimeError>(
                    this->attestationType.empty(),
                    "Error: target info not available, attestation type not set");

            memcpy_s(
                outTagetInfo,
                sizeof(sgx_target_info_t),
                &this->reportTargetInfo,
                sizeof(sgx_target_info_t));
        } // Enclave::GetTargetInfo

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::GetEnclaveCharacteristics(
            sgx_measurement_t* outEnclaveMeasurement,
            sgx_basename_t* outEnclaveBasename
            )
        {
            pdo::error::ThrowIf<pdo::error::RuntimeError>(
                    this->attestationType.empty(),
                    "Error: EnclaveCharacteristics not available, attestation type not set");
            pdo::error::ThrowIfNull(
                outEnclaveMeasurement,
                "Enclave measurement pointer is NULL");
            pdo::error::ThrowIfNull(
                outEnclaveBasename,
                "Enclave basename pointer is NULL");

            Zero(outEnclaveMeasurement, sizeof(*outEnclaveMeasurement));
            Zero(outEnclaveBasename, sizeof(*outEnclaveBasename));

            // We can get the enclave's measurement (i.e., mr_enclave) and
            // basename only by getting a quote.  To do that, we need to first
            // generate a report.

            // Now retrieve a fake enclave report so that we can later
            // create a quote from it.  We need to the quote so that we can
            // get some of the information (basename and mr_enclave,
            // specifically) being requested.
            sgx_report_t enclaveReport = { 0 };
            pdo_err_t pdoRet = PDO_SUCCESS;
            sgx_status_t ret =
                this->CallSgx(
                    [this,
                     &pdoRet,
                     &enclaveReport] () {
                        sgx_status_t ret =
                        ecall_CreateErsatzEnclaveReport(
                            this->enclaveId,
                            &pdoRet,
                            &this->reportTargetInfo,
                            &enclaveReport);
                        return error::ConvertErrorStatus(ret, pdoRet);
                    });
            pdo::error::ThrowSgxError(
                ret,
                "Failed to retrieve ersatz enclave report");
            this->ThrowPDOError(pdoRet);

            // Properly size a buffer to receive an enclave quote and then
            // retrieve it.  The enclave quote contains the basename.
            ByteArray enclaveQuoteBuffer(this->GetQuoteSize());
            this->CreateQuoteFromReport(&enclaveReport, enclaveQuoteBuffer);

            // Copy the mr_enclave and basename to the caller's buffers
            //
            // ******************IMPORTANT NOTE:
            // the quote buffer can contain any type of quote (epid or dcap);
            // epid quotes use the sgx_quote_t structure;
            // dcap quotes use the sqx_quote3_t structure;
            // the space before the repord_body field is the same in both structures;
            // hence, we can use either of them to get the mrenclave
            // clearly, basename is only meaningful in epid
            // *********************************
            sgx_quote_t* enclaveQuote =
                reinterpret_cast<sgx_quote_t *>(&enclaveQuoteBuffer[0]);
            memcpy_s(
                outEnclaveMeasurement,
                sizeof(*outEnclaveMeasurement),
                &enclaveQuote->report_body.mr_enclave,
                sizeof(*outEnclaveMeasurement));
            if(this->attestationType == "epid-linkable")
            {
                memcpy_s(
                        outEnclaveBasename,
                        sizeof(*outEnclaveBasename),
                        &enclaveQuote->basename,
                        sizeof(*outEnclaveBasename));
            }
        } // Enclave::GetEnclaveCharacteristics

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::SetSpid(
            const HexEncodedString& inSpid
            )
        {
            pdo::error::ThrowIf<pdo::error::ValueError>(
                inSpid.length() != 32,
                "Invalid SPID length");

            HexStringToBinary(this->spid.id, sizeof(this->spid.id), inSpid);
        } // Enclave::SetSpid

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::SetAttestationType(
            const std::string& inAttestationType
            )
        {
            pdo::error::ThrowIf<pdo::error::ValueError>(
                inAttestationType != "simulated" &&
                inAttestationType != "epid-linkable" &&
                inAttestationType != "dcap",
                "Invalid attestation type");

            this->attestationType = inAttestationType;

            // set the report target info based on the attestation type

            if(inAttestationType == "dcap")
            {
                quote3_error_t qe3_ret;
                qe3_ret = sgx_qe_get_target_info(&this->reportTargetInfo);
                pdo::error::ThrowIf<pdo::error::RuntimeError>(
                        SGX_QL_SUCCESS != qe3_ret,
                        "Failed to get qe target info");
            }
            else
            {
                //initialize the targetinfo and epid variables
                sgx_status_t ret = g_Enclave[0].CallSgx([this] () {
                        return sgx_init_quote(&this->reportTargetInfo, &this->epidGroupId);
                        });
                pdo::error::ThrowSgxError(ret, "Failed to initialize quote");
            }
        } // Enclave::SetAttestationType

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::SetSignatureRevocationList(
            const std::string& inSignatureRevocationList
            )
        {
            // Copy the signature revocation list to our internal cached
            // version and then retrieve the, potentially, new quote size
            // and cache that value.
            this->signatureRevocationList = inSignatureRevocationList;
        } // Enclave::SetSignatureRevocationList

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        const uint8_t* Enclave::GetSignatureRevocationList(uint32_t* pRevocationListSize) const
        {
            const uint8_t* pRevocationList = nullptr;
            *pRevocationListSize = this->signatureRevocationList.size();
            if (*pRevocationListSize) {
                pRevocationList =
                    reinterpret_cast<const uint8_t *>(
                        this->signatureRevocationList.c_str());
            }
            return pRevocationList;
        } // Enclave::GetSignatureRevocationList

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::CreateDCAPQuoteFromReport(
            const sgx_report_t* inEnclaveReport,
            ByteArray& outEnclaveQuote
            )
        {
            pdo::error::ThrowIfNull(
                inEnclaveReport,
                "Enclave report pointer is NULL");

            //dcap quote
            quote3_error_t qe3_ret;

            outEnclaveQuote.resize(this->GetQuoteSize());

            qe3_ret = sgx_qe_get_quote(
                    inEnclaveReport,
                    outEnclaveQuote.size(),
                    reinterpret_cast<uint8_t *>(&outEnclaveQuote[0]));
            pdo::error::ThrowIf<pdo::error::RuntimeError>(
                    SGX_QL_SUCCESS != qe3_ret,
                    "Failed to get quote");
        } // Enclave::CreateDCAPQuoteFromReport

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::CreateEPIDQuoteFromReport(
            const sgx_report_t* inEnclaveReport,
            ByteArray& outEnclaveQuote
            )
        {
            pdo::error::ThrowIfNull(
                inEnclaveReport,
                "Enclave report pointer is NULL");

            uint32_t rlSize;
            const uint8_t* pRevocationList = this->GetSignatureRevocationList(&rlSize);

            // Properly size the enclave quote buffer for the caller and zero it
            // out so we have predicatable contents.
            outEnclaveQuote.resize(this->GetQuoteSize());

            sgx_status_t sresult =
                this->CallSgx(
                    [this,
                     &inEnclaveReport,
                     pRevocationList,
                     rlSize,
                     &outEnclaveQuote] () {
                        return
                        sgx_get_quote(
                            inEnclaveReport,
                            SGX_LINKABLE_SIGNATURE,
                            &this->spid,
                            nullptr,
                            pRevocationList,
                            rlSize,
                            nullptr,
                            reinterpret_cast<sgx_quote_t *>(&outEnclaveQuote[0]),
                            static_cast<uint32_t>(outEnclaveQuote.size()));
                    });
            pdo::error::ThrowSgxError(
                sresult,
                "Failed to create linkable quote for enclave report");
        } // Enclave::CreateEPIDQuoteFromReport

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::CreateQuoteFromReport(
            const sgx_report_t* inEnclaveReport,
            ByteArray& outEnclaveQuote
            )
        {
            if(this->attestationType == "dcap")
            {
                this->CreateDCAPQuoteFromReport(inEnclaveReport, outEnclaveQuote);
            }
            else
            {
                this->CreateEPIDQuoteFromReport(inEnclaveReport, outEnclaveQuote);
            }
        } // Enclave::CreateQuoteFromReport

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        // XX Private helper methods                                 XX
        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::ThrowPDOError(
            pdo_err_t err
            )
        {
            if(err != PDO_SUCCESS) {
                std::string tmp(this->enclaveError);
                this->enclaveError.clear();
                throw error::Error(err, tmp.c_str());
            }
        } // Enclave::ThrowPDOError

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::LoadEnclave()
        {
            if (!this->enclaveId) {
                /* Enclave id, used in communicating with enclave */
                Enclave::QuerySgxStatus();

                sgx_launch_token_t token = { 0 };
                int flags = SGX_DEBUG_FLAG;
                pdo::error::ThrowSgxError((SGX_DEBUG_FLAG==0 ? SGX_ERROR_UNEXPECTED:SGX_SUCCESS),
                    "SGX DEBUG flag is 0 (possible cause: wrong compile flags)");

                // First attempt to load the enclave executable
                sgx_status_t ret = SGX_SUCCESS;
                ret = this->CallSgx([this, flags, &token] () {
                        int updated = 0;
                        return sgx_create_enclave(
                            this->enclaveFilePath.c_str(),
                            flags,
                            &token,
                            &updated,
                            &this->enclaveId,
                            NULL);
                    },
                    10, // retries
                    250 // retryWaitMs
                    );
                pdo::error::ThrowSgxError(ret, "Unable to create enclave.");

                // Initialize the enclave
                pdo_err_t pdoError = PDO_SUCCESS;
                ret = this->CallSgx([this, &pdoError] () {
                        sgx_status_t ret =
                        ecall_Initialize(
                            this->enclaveId,
                            &pdoError);
                        return error::ConvertErrorStatus(ret, pdoError);
                    });
                pdo::error::ThrowSgxError(ret, "Enclave call to ecall_Initialize failed");
                this->ThrowPDOError(pdoError);

                // We need to figure out a priori the size of the sealed signup
                // data so that caller knows the proper size for the buffer when
                // creating signup data.
                ret =
                    this->CallSgx([this, &pdoError] () {
                            sgx_status_t ret =
                            ecall_CalculateSealedEnclaveDataSize(
                                this->enclaveId,
                                &pdoError,
                                &this->sealedSignupDataSize);
                            return
                            error::ConvertErrorStatus(ret, pdoError);
                        });
                pdo::error::ThrowSgxError(
                    ret,
                    "Failed to calculate length of sealed signup data");
                this->ThrowPDOError(pdoError);
            }
        } // Enclave::LoadEnclave

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        sgx_status_t Enclave::CallSgx(
            std::function<sgx_status_t (void)> fxn,
            int retries,
            int retryDelayMs
            )
        {
            sgx_status_t ret = SGX_SUCCESS;
            int count = 0;
            bool retry = true;
            do {
                ret = fxn();
                if (SGX_ERROR_ENCLAVE_LOST == ret) {
                    // Enclave lost, potentially due to power state change
                    // reload the enclave and try again
                    this->LoadEnclave();
                } else if (SGX_ERROR_DEVICE_BUSY == ret) {
                    // Device is busy... wait and try again.
                    usleep(retryDelayMs  * 1000);
                    count++;
                    retry = count <= retries;
                } else {
                    // Not an error code we need to handle here,
                    // exit the loop and let the calling function handle it.
                    retry = false;
                }
            } while (retry);

            return ret;
        } // Enclave::CallSgx

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

        /* This function is run as the very first step in the attestation
           process to check the device status; query the status of the SGX
           device.  If not enabled before, enable it. If the device is not
           enabled, SGX device not found error is expected when the enclave is
           created.
        */
        void Enclave::QuerySgxStatus()
        {
            sgx_device_status_t sgx_device_status;
            sgx_status_t ret = sgx_enable_device(&sgx_device_status);
            pdo::error::ThrowSgxError(ret);

            switch (sgx_device_status) {
            case SGX_ENABLED:
                break;
            case SGX_DISABLED_REBOOT_REQUIRED:
                throw pdo::error::RuntimeError(
                    "SGX device will be enabled after this machine is "
                    "rebooted.\n");
                break;
            case SGX_DISABLED_LEGACY_OS:
                throw pdo::error::RuntimeError(
                    "SGX device can't be enabled on an OS that doesn't "
                    "support EFI interface.\n");
                break;
            case SGX_DISABLED:
                throw pdo::error::RuntimeError("SGX device not found.\n");
                break;
            default:
                throw pdo::error::RuntimeError("Unexpected error.\n");
                break;
            }
        } // Enclave::QuerySgxStatus

    } // enclave_api

} // namespace pdo
