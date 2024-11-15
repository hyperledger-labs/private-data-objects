# Copyright 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

SET(ITA_ROOT_CACERT_FILE ITA_RootCA.jwk)
SET(ITA_CERTIFICATES_H_FILE ita-certificates.h)

SET(CERTIFICATE_INCLUDE_PATH ${CMAKE_BINARY_DIR} PARENT_SCOPE)

IF (NOT DEFINED ENV{ITA_ROOT_CACERT_URL})
    MESSAGE(WARNING "No ITA certs url in ITA_ROOT_CACERT_URL: an empty root cert will be used (DCAP verifications will fail)")
    FILE(TOUCH
        ${CMAKE_BINARY_DIR}/${ITA_ROOT_CACERT_FILE}
        )
ELSE()
    FILE(DOWNLOAD
        $ENV{ITA_ROOT_CACERT_URL}
        ${CMAKE_BINARY_DIR}/${ITA_ROOT_CACERT_FILE}
        TLS_VERIFY ON
        SHOW_PROGRESS
    )
ENDIF()

FILE(READ
    ${CMAKE_BINARY_DIR}/${ITA_ROOT_CACERT_FILE}
    INTEL_ROOT_CA_JWT
    )

FILE(WRITE ${CMAKE_BINARY_DIR}/${ITA_CERTIFICATES_H_FILE}
    "
#ifndef ITA_CERTIFICATES_H
#define ITA_CERTIFICATES_H

/*
 * Copyright 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
extern const char ita_token_signing_ca_cert_jwt[] =
R\"MLT(${INTEL_ROOT_CA_JWT}
)MLT\"
;

#endif
")
