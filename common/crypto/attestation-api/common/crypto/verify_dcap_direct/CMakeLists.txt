# Copyright 2024 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

SET(DCAP_ROOT_CACERT_FILE DCAP_RootCA.pem)
SET(DCAP_CERTIFICATES_H_FILE dcap-certificates.h)

SET(CERTIFICATE_INCLUDE_PATH ${CMAKE_BINARY_DIR} PARENT_SCOPE)

SET(DCAP_ROOT_CACERT_URL "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem")
    
FILE(DOWNLOAD
    "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"
    ${CMAKE_BINARY_DIR}/${DCAP_ROOT_CACERT_FILE}
    TLS_VERIFY ON
    SHOW_PROGRESS
    )

FILE(READ
    ${CMAKE_BINARY_DIR}/${DCAP_ROOT_CACERT_FILE}
    INTEL_ROOT_CA_PEM
    )

FILE(WRITE ${CMAKE_BINARY_DIR}/${DCAP_CERTIFICATES_H_FILE}
    "
#ifndef DCAP_CERTIFICATES_H
#define DCAP_CERTIFICATES_H

/*
 * Copyright 2024 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
extern const char dcap_ca_cert_pem[] =
R\"MLT(${INTEL_ROOT_CA_PEM}
)MLT\"
;

#endif
")
