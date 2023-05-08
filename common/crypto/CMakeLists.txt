# Copyright 2020 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CMAKE_MINIMUM_REQUIRED(VERSION 3.10 FATAL_ERROR)

# NOTE: this file is included by the common CMakeLists.txt;
# it should not be evaluated independently

FILE(GLOB PROJECT_HEADERS_ *.h)
FILE(GLOB PROJECT_SOURCES *.cpp)

FILE(GLOB IAS_HEADERS verify_ias_report/*.h)
FILE(GLOB IAS_SOURCES verify_ias_report/*.cpp)

################################################################################
# Common crypto settings
################################################################################
IF (DEFINED ENV{PDO_DEFAULT_SIGCURVE})
    SET(PDO_DEFAULT_SIGCURVE "PDO_DEFAULT_SIGCURVE=$ENV{PDO_DEFAULT_SIGCURVE}")
ELSE()
    SET(PDO_DEFAULT_SIGCURVE "PDO_DEFAULT_SIGCURVE=SECP256K1")
ENDIF()

################################################################################
# IAS generated sources
#
# Builds the ias-certificates.cpp file using the script. This is not used
# by the client (ias verification requires sgx).
################################################################################

IF (BUILD_TRUSTED OR BUILD_UNTRUSTED)
  SET(CRYPTO_BUILD_DIR ${CMAKE_BINARY_DIR}/crypto)
  SET(INTEL_ROOT_CACERT_PATH ${CRYPTO_BUILD_DIR}/Intel_SGX_Attestation_RootCA.pem)
  SET(IAS_CERTIFICATES_H_PATH ${CRYPTO_BUILD_DIR}/ias-certificates.h)

  FILE(DOWNLOAD
      https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.pem
      ${INTEL_ROOT_CACERT_PATH}
      TLS_VERIFY ON
      SHOW_PROGRESS
  )
  FILE(READ
      ${INTEL_ROOT_CACERT_PATH}
      INTEL_ROOT_CA_PEM
  )
  # create the header file containing the root CA certificate stored as a global variable
  FILE(WRITE ${IAS_CERTIFICATES_H_PATH}
      "
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
")
ENDIF()

################################################################################
# Trusted Crypto library
################################################################################
IF (BUILD_TRUSTED)
  ADD_LIBRARY(${T_CRYPTO_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES} ${IAS_HEADERS} ${IAS_SOURCES})
  SGX_PREPARE_TRUSTED(${T_CRYPTO_LIB_NAME})

  #include the crypto build dir to help find the cmake generated headers
  TARGET_INCLUDE_DIRECTORIES(${T_CRYPTO_LIB_NAME} PRIVATE ${CRYPTO_BUILD_DIR})

  TARGET_COMPILE_DEFINITIONS(${T_CRYPTO_LIB_NAME} PRIVATE ${PDO_DEFAULT_SIGCURVE})
ENDIF()

################################################################################
# Untrusted Crypto library
################################################################################
IF (BUILD_UNTRUSTED)
  ADD_LIBRARY(${U_CRYPTO_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES} ${IAS_HEADERS} ${IAS_SOURCES})
  SGX_PREPARE_UNTRUSTED(${U_CRYPTO_LIB_NAME})

  #include the crypto build dir to help find the cmake generated headers
  TARGET_INCLUDE_DIRECTORIES(${U_CRYPTO_LIB_NAME} PRIVATE ${CRYPTO_BUILD_DIR})

  TARGET_COMPILE_DEFINITIONS(${U_CRYPTO_LIB_NAME} PRIVATE ${PDO_DEFAULT_SIGCURVE})

  # critical flag for conditional compile in source code
  TARGET_COMPILE_DEFINITIONS(${U_CRYPTO_LIB_NAME} PRIVATE "_UNTRUSTED_=1")
ENDIF()

################################################################################
# Client-Only Crypto library
################################################################################
IF (BUILD_CLIENT)
  ADD_LIBRARY(${C_CRYPTO_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})

  TARGET_COMPILE_DEFINITIONS(${C_CRYPTO_LIB_NAME} PRIVATE ${PDO_DEFAULT_SIGCURVE})

  # critical flags for conditional compile in source code
  TARGET_COMPILE_DEFINITIONS(${C_CRYPTO_LIB_NAME} PRIVATE "_UNTRUSTED_=1")
  TARGET_COMPILE_DEFINITIONS(${C_CRYPTO_LIB_NAME} PRIVATE "_CLIENT_ONLY_=1")
ENDIF()
