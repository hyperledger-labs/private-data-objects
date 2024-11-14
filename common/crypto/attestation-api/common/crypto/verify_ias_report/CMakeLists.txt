# Copyright 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

SET(INTEL_ROOT_CACERT_FILE Intel_SGX_Attestation_RootCA.pem)
SET(IAS_CERTIFICATES_H_FILE ias-certificates.h)

SET(CERTIFICATE_INCLUDE_PATH ${CMAKE_BINARY_DIR} PARENT_SCOPE)

FILE(DOWNLOAD
    https://certificates.trustedservices.intel.com/${INTEL_ROOT_CACERT_FILE}
    ${CMAKE_BINARY_DIR}/${INTEL_ROOT_CACERT_FILE}
    TLS_VERIFY ON
    SHOW_PROGRESS
    )

FILE(READ
    ${CMAKE_BINARY_DIR}/${INTEL_ROOT_CACERT_FILE}
    INTEL_ROOT_CA_PEM
    )

FILE(WRITE ${CMAKE_BINARY_DIR}/${IAS_CERTIFICATES_H_FILE}
    "
#ifndef IAS_CERTIFICATES_H
#define IAS_CERTIFICATES_H

/*
 * Copyright 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
extern const char ias_report_signing_ca_cert_pem[] =
R\"MLT(${INTEL_ROOT_CA_PEM}
)MLT\"
;

#endif
")
