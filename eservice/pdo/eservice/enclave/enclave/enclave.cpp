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
#include <algorithm>

#include <sgx_uae_epid.h>
#include "sgx_support.h"

#include "log.h"

#include "error.h"
#include "hex_string.h"
#include "pdo_error.h"
#include "types.h"
#include "zero.h"

#include "enclave.h"

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
            sealedSignupDataSize(0)
        {
            uint32_t size;
            sgx_status_t ret = sgx_calc_quote_size(nullptr, 0, &size);
            pdo::error::ThrowSgxError(ret, "Failed to get SGX quote size.");
            this->quoteSize = size;

            //initialize the targetinfo and epid variables
            ret = g_Enclave[0].CallSgx([this] () {
                    return sgx_init_quote(&this->reportTargetInfo, &this->epidGroupId);
                });
            pdo::error::ThrowSgxError(ret, "Failed to initialized quote in enclave constructore");
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

            pdo::logger::LogV(PDO_LOG_DEBUG, "Enclave::Worker[%ld] %ld", (long)enc->GetEnclaveId(), enc->GetThreadId());

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
            pdo::logger::LogV(PDO_LOG_DEBUG, "Enclave::ShutdownWorker[%ld]", (long)this->GetEnclaveId());

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

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::GetEpidGroup(
            sgx_epid_group_id_t* outEpidGroup
            )
        {
            sgx_status_t ret;
            //retrieve epid by calling init quote
            ret = g_Enclave[0].CallSgx([this] () {
                        return sgx_init_quote(&this->reportTargetInfo, &this->epidGroupId);
                    });
            pdo::error::ThrowSgxError(ret, "Failed to get epid group id from init_quote");

            //copy epid group into output parameter
            memcpy_s(
                outEpidGroup,
                sizeof(sgx_epid_group_id_t),
                &this->epidGroupId,
                sizeof(sgx_epid_group_id_t));
        } // Enclave::GetEpidGroup

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::GetEnclaveCharacteristics(
            sgx_measurement_t* outEnclaveMeasurement,
            sgx_basename_t* outEnclaveBasename
            )
        {
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

            // Initialize a quote
            sgx_target_info_t targetInfo = { 0 };
            sgx_epid_group_id_t gid = { 0 };

            sgx_status_t ret = this->CallSgx([&targetInfo, &gid] () {
                    return sgx_init_quote(&targetInfo, &gid);
                });
            pdo::error::ThrowSgxError(ret, "Failed to initialize enclave quote");

            // Now retrieve a fake enclave report so that we can later
            // create a quote from it.  We need to the quote so that we can
            // get some of the information (basename and mr_enclave,
            // specifically) being requested.
            sgx_report_t enclaveReport = { 0 };
            pdo_err_t pdoRet = PDO_SUCCESS;
            ret =
                this->CallSgx(
                    [this,
                     &pdoRet,
                     &targetInfo,
                     &enclaveReport] () {
                        sgx_status_t ret =
                        ecall_CreateErsatzEnclaveReport(
                            this->enclaveId,
                            &pdoRet,
                            &targetInfo,
                            &enclaveReport);
                        return error::ConvertErrorStatus(ret, pdoRet);
                    });
            pdo::error::ThrowSgxError(
                ret,
                "Failed to retrieve ersatz enclave report");
            this->ThrowPDOError(pdoRet);

            // Properly size a buffer to receive an enclave quote and then
            // retrieve it.  The enclave quote contains the basename.
            ByteArray enclaveQuoteBuffer(this->quoteSize);
            sgx_quote_t* enclaveQuote =
                reinterpret_cast<sgx_quote_t *>(&enclaveQuoteBuffer[0]);
            const uint8_t* pRevocationList = nullptr;
            if (this->signatureRevocationList.size()) {
                pRevocationList =
                    reinterpret_cast<const uint8_t *>(
                        this->signatureRevocationList.c_str());
            }

            ret =
                this->CallSgx(
                    [this,
                     &enclaveReport,
                     pRevocationList,
                     &enclaveQuoteBuffer] () {
                        return
                        sgx_get_quote(
                            &enclaveReport,
                            SGX_LINKABLE_SIGNATURE,
                            &this->spid,
                            nullptr,
                            pRevocationList,
                            static_cast<uint32_t>(
                                this->signatureRevocationList.size()),
                            nullptr,
                            reinterpret_cast<sgx_quote_t *>(
                                &enclaveQuoteBuffer[0]),
                            static_cast<uint32_t>(enclaveQuoteBuffer.size()));
                    });
            pdo::error::ThrowSgxError(
                ret,
                "Failed to create linkable quote for enclave report");

            // Copy the mr_enclave and basenaeme to the caller's buffers
            memcpy_s(
                outEnclaveMeasurement,
                sizeof(*outEnclaveMeasurement),
                &enclaveQuote->report_body.mr_enclave,
                sizeof(*outEnclaveMeasurement));
            memcpy_s(
                outEnclaveBasename,
                sizeof(*outEnclaveBasename),
                &enclaveQuote->basename,
                sizeof(*outEnclaveBasename));
        } // Enclave::GetEnclaveCharacteristics

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::SetSpid(
            const HexEncodedString& inSpid
            )
        {
            // check SPID length
            pdo::error::ThrowIf<pdo::error::ValueError>(
                inSpid.length() != 32,
                "Invalid SPID length");

            // check SPID format
            pdo::error::ThrowIf<pdo::error::ValueError>(
                ! std::all_of(inSpid.begin(), inSpid.end(), ::isxdigit),
                "Invalid SPID format");

            HexStringToBinary(this->spid.id, sizeof(this->spid.id), inSpid);
        } // Enclave::SetSpid

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::SetSignatureRevocationList(
            const std::string& inSignatureRevocationList
            )
        {
            // Copy the signature revocation list to our internal cached
            // version and then retrieve the, potentially, new quote size
            // and cache that value.
            this->signatureRevocationList = inSignatureRevocationList;

            const uint8_t* pRevocationList = nullptr;
            uint32_t revocationListSize = this->signatureRevocationList.size();
            if (revocationListSize) {
                pRevocationList =
                    reinterpret_cast<const uint8_t *>(
                        this->signatureRevocationList.c_str());
            }

            uint32_t size;
            pdo::error::ThrowSgxError(sgx_calc_quote_size(pRevocationList, revocationListSize, &size));
            this->quoteSize = size;
        } // Enclave::SetSignatureRevocationList

        // XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        void Enclave::CreateQuoteFromReport(
            const sgx_report_t* inEnclaveReport,
            ByteArray& outEnclaveQuote
            )
        {
            pdo::error::ThrowIfNull(
                inEnclaveReport,
                "Enclave report pointer is NULL");
            const uint8_t* pRevocationList = nullptr;
            if (this->signatureRevocationList.size()) {
                pRevocationList =
                    reinterpret_cast<const uint8_t *>(
                        this->signatureRevocationList.c_str());
            }

            // Properly size the enclave quote buffer for the caller and zero it
            // out so we have predicatable contents.
            outEnclaveQuote.resize(this->quoteSize);

            sgx_status_t sresult =
                this->CallSgx(
                    [this,
                     &inEnclaveReport,
                     pRevocationList,
                     &outEnclaveQuote] () {
                        return
                        sgx_get_quote(
                            inEnclaveReport,
                            SGX_LINKABLE_SIGNATURE,
                            &this->spid,
                            nullptr,
                            pRevocationList,
                            static_cast<uint32_t>(
                                this->signatureRevocationList.size()),
                            nullptr,
                            reinterpret_cast<sgx_quote_t *>(&outEnclaveQuote[0]),
                            static_cast<uint32_t>(outEnclaveQuote.size()));
                    });
            pdo::error::ThrowSgxError(
                sresult,
                "Failed to create linkable quote for enclave report");
        } // Enclave::GenerateSignupData

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

                pdo::logger::LogV(PDO_LOG_DEBUG, "LoadEnclave, SGX_DEBUG_FLAG: %d", SGX_DEBUG_FLAG);

                // First attempt to load the enclave executable
                sgx_status_t ret = SGX_SUCCESS;
                ret = this->CallSgx([this, &token] () {
                        int updated = 0;
                        return sgx_create_enclave(
                            this->enclaveFilePath.c_str(),
                            SGX_DEBUG_FLAG,
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
