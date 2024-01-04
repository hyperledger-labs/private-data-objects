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
  SET(PROJECT_GENERATED_IAS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/verify_ias_report/ias-certificates.txt)
  SET_SOURCE_FILES_PROPERTIES(${PROJECT_GENERATED_IAS_SOURCES} PROPERTIES GENERATED TRUE)
  SET(FETCH_IAS_CERTS ${CMAKE_CURRENT_SOURCE_DIR}/verify_ias_report/fetch_ias_certificates.sh)

  ADD_CUSTOM_COMMAND(
    OUTPUT  ${PROJECT_GENERATED_IAS_SOURCES}
    COMMAND ${FETCH_IAS_CERTS} ${IAS_CERTIFICATE_URL} ${PROJECT_GENERATED_IAS_SOURCES}
    DEPENDS ${FETCH_IAS_CERTS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/verify_ias_report
  )

  ADD_CUSTOM_TARGET(generate-ias-files DEPENDS ${PROJECT_GENERATED_IAS_SOURCES})

  SET_PROPERTY(
    TARGET generate-ias-files
    APPEND
    PROPERTY ADDITIONAL_CLEAN_FILES ${PROJECT_GENERATED_IAS_SOURCE})

  IF (${SGX_MODE} STREQUAL "HW")
    SET(IAS_CA_CERT_REQUIRED "IAS_CA_CERT_REQUIRED=1")
  ENDIF()

  LIST(APPEND IAS_SOURCES ${PROJECT_GENERATED_IAS_SOURCES})
ENDIF()

################################################################################
# Trusted Crypto library
################################################################################
IF (BUILD_TRUSTED)
  ADD_LIBRARY(${T_CRYPTO_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES} ${IAS_HEADERS} ${IAS_SOURCES})
  ADD_DEPENDENCIES(${T_CRYPTO_LIB_NAME} generate-ias-files)
  SGX_PREPARE_TRUSTED(${T_CRYPTO_LIB_NAME})

  TARGET_COMPILE_DEFINITIONS(${T_CRYPTO_LIB_NAME} PRIVATE ${PDO_DEFAULT_SIGCURVE})
  TARGET_COMPILE_DEFINITIONS(${T_CRYPTO_LIB_NAME} PRIVATE ${IAS_CA_CERT_REQUIRED})
ENDIF()

################################################################################
# Untrusted Crypto library
################################################################################
IF (BUILD_UNTRUSTED)
  ADD_LIBRARY(${U_CRYPTO_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES} ${IAS_HEADERS} ${IAS_SOURCES})
  ADD_DEPENDENCIES(${U_CRYPTO_LIB_NAME} generate-ias-files)
  SGX_PREPARE_UNTRUSTED(${U_CRYPTO_LIB_NAME})

  TARGET_COMPILE_DEFINITIONS(${U_CRYPTO_LIB_NAME} PRIVATE ${PDO_DEFAULT_SIGCURVE})
  TARGET_COMPILE_DEFINITIONS(${U_CRYPTO_LIB_NAME} PRIVATE ${IAS_CA_CERT_REQUIRED})

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
