# Copyright 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13)

PROJECT(ATTESTATION-API)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

INCLUDE(CMakeVariables.txt)

IF (NOT DEFINED ENV{DCAP_PRIMITIVES})
  MESSAGE(FATAL_ERROR "DCAP_PRIMITIVES variable with source repo path not defined")
ENDIF()

###################################################################################################
# First run cmake in common
###################################################################################################
# This patches the jwt repo for sgx use
ADD_SUBDIRECTORY(common)

###################################################################################################
# Set up trusted certificates in headers
###################################################################################################

# This creates the necessary headers which include the trusted certificates
# and returns sets CERTIFICATE_INCLUDE_PATH to find them
ADD_SUBDIRECTORY(common/crypto/verify_ias_report)
LIST(APPEND CERTIFICATE_INCLUDE_PATHS "${CERTIFICATE_INCLUDE_PATH}")

ADD_SUBDIRECTORY(common/crypto/verify_ita_token)
LIST(APPEND CERTIFICATE_INCLUDE_PATHS "${CERTIFICATE_INCLUDE_PATH}")

ADD_SUBDIRECTORY(common/crypto/verify_dcap_direct)
LIST(APPEND CERTIFICATE_INCLUDE_PATHS "${CERTIFICATE_INCLUDE_PATH}")

###################################################################################################
# Logging
###################################################################################################

# Prepare the logging libs.
# Note: by default, no trusted logging and untrusted logging is printf.
# This returns the variables: LOGGING_UNTRUSTED_INCLUDE_PATH, LOGGING_TRUSTED_INCLUDE_PATH
ADD_SUBDIRECTORY(common/logging)

###################################################################################################
# Project files and headers
###################################################################################################

FILE(GLOB PROJECT_HEADERS
    "include/*.h"
    "${CERTIFICATE_INCLUDE_PATH}/*.h"
    )

FILE(GLOB PROJECT_SOURCES
    "evidence/*.cpp"
    "common/base64/base64.cpp"
    "common/types/*.cpp"
    "common/crypto/*.cpp"
    "common/crypto/verify_ias_report/*.cpp"
    "common/crypto/verify_ita_token/*.cpp"
    "common/crypto/verify_dcap_direct/*.cpp"
    )

FILE(GLOB PROJECT_OCALLS
    "ocalls/*.c"
    )

FILE(GLOB PROJECT_TRUSTED_SOURCES
    "attestation/*.cpp"
    $ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationLibrary/src/*.cpp
    $ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationLibrary/src/OpensslHelpers/*.cpp
    $ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationLibrary/src/PckParser/*.cpp
    $ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationLibrary/src/CertVerification/*.cpp
    $ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationLibrary/src/QuoteVerification/*.cpp
    $ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationLibrary/src/Verifiers/*.cpp
    $ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationLibrary/src/Verifiers/Checks/*.cpp
    $ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationLibrary/src/Utils/*.cpp
    $ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationLibrary/include/SgxEcdsaAttestation/*.h
    )

SET(DCAP_QG_PATH "$ENV{DCAP_PRIMITIVES}/QuoteGeneration")
SET(DCAP_QV_PATH "$ENV{DCAP_PRIMITIVES}/QuoteVerification")

###################################################################################################
# Tools
###################################################################################################
SET(B64ATTESTATION_TO_B64COLLATERAL "b64attestation_to_b64collateral")
ADD_EXECUTABLE(${B64ATTESTATION_TO_B64COLLATERAL}
	conversion/dcap-direct/b64attestation2b64collateral.cpp
	common/base64/base64.cpp)
ADD_CUSTOM_COMMAND(TARGET ${B64ATTESTATION_TO_B64COLLATERAL}
	POST_BUILD
	COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/conversion/dcap-direct/ &&
        mv $<TARGET_FILE:${B64ATTESTATION_TO_B64COLLATERAL}> ${CMAKE_CURRENT_BINARY_DIR}/conversion/dcap-direct/)

TARGET_INCLUDE_DIRECTORIES(${B64ATTESTATION_TO_B64COLLATERAL} PRIVATE common)

# newer DCAP (1.22) libs need the qal (older, 1.19, don't)
SET(DCAP_LINK_LIBS ${DCAP_QV_PATH}/appraisal/qal/libdcap_qal.a)

TARGET_LINK_LIBRARIES(${B64ATTESTATION_TO_B64COLLATERAL}
    #${DCAP_QV_PATH}/dcap_quoteverify/linux/libsgx_dcap_quoteverify.a
    #${DCAP_QG_PATH}/build/linux/libdcap_quoteprov.a
    #${DCAP_QG_PATH}/build/linux/libsgx_default_qcnl_wrapper.a
    #sgx_dcap_quoteverify dcap_quoteprov sgx_default_qcnl_wrapper
    sgx_dcap_quoteverify
    # sgx_dcap_ql dcap_quoteprov necessary for the callbacks
    sgx_dcap_ql
    dcap_quoteprov
    )

###################################################################################################
# Untrusted one-attestation library
###################################################################################################

SET(U_OA_LIB_STATIC ${U_ONE_ATTESTATION_LIB_NAME}_Static)

ADD_LIBRARY(${U_OA_LIB_STATIC} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES} ${PROJECT_OCALLS})

TARGET_INCLUDE_DIRECTORIES(${U_OA_LIB_STATIC} PRIVATE "$ENV{SGX_SDK}/include")
TARGET_INCLUDE_DIRECTORIES(${U_OA_LIB_STATIC} PRIVATE "include")
TARGET_INCLUDE_DIRECTORIES(${U_OA_LIB_STATIC} BEFORE PRIVATE "common")
TARGET_INCLUDE_DIRECTORIES(${U_OA_LIB_STATIC} PRIVATE "common/nlohmann/json/include")
TARGET_INCLUDE_DIRECTORIES(${U_OA_LIB_STATIC} PRIVATE "common/jwt-cpp/include")
TARGET_INCLUDE_DIRECTORIES(${U_OA_LIB_STATIC} PRIVATE ${CERTIFICATE_INCLUDE_PATHS})
TARGET_INCLUDE_DIRECTORIES(${U_OA_LIB_STATIC} PRIVATE ${LOGGING_UNTRUSTED_INCLUDE_PATH})

TARGET_INCLUDE_DIRECTORIES(${U_OA_LIB_STATIC} PRIVATE "$ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/Build/Release/dist/include/")
TARGET_INCLUDE_DIRECTORIES(${U_OA_LIB_STATIC} PRIVATE "$ENV{DCAP_PRIMITIVES}")
TARGET_INCLUDE_DIRECTORIES(${U_OA_LIB_STATIC} PRIVATE "$ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationLibrary/src")
TARGET_INCLUDE_DIRECTORIES(${U_OA_LIB_STATIC} PRIVATE "$ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationCommons/include")

TARGET_COMPILE_OPTIONS(${U_OA_LIB_STATIC} PRIVATE -fvisibility=hidden)
TARGET_COMPILE_OPTIONS(${U_OA_LIB_STATIC} PRIVATE -fpie)
TARGET_COMPILE_OPTIONS(${U_OA_LIB_STATIC} PRIVATE -fstack-protector)

SET(QVL_LIB_PATH "$ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/Build/Release/dist/lib")

add_custom_target(combined_u_static_target ALL
    COMMAND mkdir -p oals_objs lqvs_objs lacs_objs laps_objs
    COMMAND ar -x --output oals_objs $<TARGET_FILE:${U_OA_LIB_STATIC}>
    COMMAND ar -x --output lqvs_objs ${QVL_LIB_PATH}/libQuoteVerificationStatic.a
    COMMAND ar -x --output lacs_objs ${QVL_LIB_PATH}/libAttestationCommonsStatic.a
    COMMAND ar -x --output laps_objs ${QVL_LIB_PATH}/libAttestationParsersStatic.a
    COMMAND ar -qcs lib${U_ONE_ATTESTATION_LIB_NAME}.a oals_objs/*.o lqvs_objs/*.o lacs_objs/*.o laps_objs/*.o
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS ${U_OA_LIB_STATIC}
    )
ADD_LIBRARY(${U_ONE_ATTESTATION_LIB_NAME} STATIC IMPORTED)
ADD_DEPENDENCIES(${U_ONE_ATTESTATION_LIB_NAME} combined_u_static_target)
SET_TARGET_PROPERTIES(${U_ONE_ATTESTATION_LIB_NAME}
    PROPERTIES
    IMPORTED_LOCATION lib${U_ONE_ATTESTATION_LIB_NAME}.a
    )

###################################################################################################
# Trusted one-attestation library
###################################################################################################

SET(T_OA_LIB_STATIC ${T_ONE_ATTESTATION_LIB_NAME}_Static)
ADD_LIBRARY(${T_OA_LIB_STATIC} STATIC
    ${PROJECT_HEADERS} ${PROJECT_TRUSTED_HEADERS} ${PROJECT_SOURCES} ${PROJECT_TRUSTED_SOURCES})

#dependency in common to ensure the jwt lib is patched for building the trusted lib in SGX
ADD_DEPENDENCIES(${T_OA_LIB_STATIC} patch_jwt)

TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE "common/sgx-support") # for clocale, before sgxsdk includes
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE "$ENV{SGX_SDK}/include")
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE "$ENV{SGX_SDK}/include/libcxx")
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE "$ENV{SGX_SDK}/include/tlibc")
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE "$ENV{SGX_SSL}/include")
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE "include")
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} BEFORE PRIVATE "common")
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE "common/nlohmann/json/include")
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE "common/jwt-cpp/include")
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE ${CERTIFICATE_INCLUDE_PATHS})
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE ${LOGGING_TRUSTED_INCLUDE_PATH})

TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE "$ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/Build/Release/dist/include/")
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE "$ENV{DCAP_PRIMITIVES}")
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE "$ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationLibrary/src")
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE "$ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/AttestationCommons/include")
TARGET_INCLUDE_DIRECTORIES(${T_OA_LIB_STATIC} PRIVATE  "$ENV{DCAP_PRIMITIVES}/QuoteVerification/QVL/Src/ThirdParty/rapidjson/include")

TARGET_COMPILE_OPTIONS(${T_OA_LIB_STATIC} PRIVATE -nostdinc++)
TARGET_COMPILE_OPTIONS(${T_OA_LIB_STATIC} PRIVATE -fvisibility=hidden)
TARGET_COMPILE_OPTIONS(${T_OA_LIB_STATIC} PRIVATE -fpie)
TARGET_COMPILE_OPTIONS(${T_OA_LIB_STATIC} PRIVATE -fstack-protector)

#remove time-related code from jwt tool (as dcap primitives do)
TARGET_COMPILE_OPTIONS(${T_OA_LIB_STATIC} PRIVATE -DSGX_JWT)

add_custom_target(combined_t_static_target ALL
    COMMAND mkdir -p toals_objs lacse_objs lapse_objs
    COMMAND ar -x --output toals_objs $<TARGET_FILE:${T_OA_LIB_STATIC}>
    COMMAND ar -x --output lacse_objs ${QVL_LIB_PATH}/libAttestationCommonsStaticEnclave.a
    COMMAND ar -x --output lapse_objs ${QVL_LIB_PATH}/libAttestationParsersStaticEnclave.a
    COMMAND ar -qcs lib${T_ONE_ATTESTATION_LIB_NAME}.a toals_objs/*.o lacse_objs/*.o lapse_objs/*.o
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS ${U_OA_LIB_STATIC}
    )
ADD_LIBRARY(${T_ONE_ATTESTATION_LIB_NAME} STATIC IMPORTED)
ADD_DEPENDENCIES(${T_ONE_ATTESTATION_LIB_NAME} combined_t_static_target)
SET_TARGET_PROPERTIES(${T_ONE_ATTESTATION_LIB_NAME}
    PROPERTIES
    IMPORTED_LOCATION lib${T_ONE_ATTESTATION_LIB_NAME}.a
    )


###################################################################################################
# Local Tests
###################################################################################################
ENABLE_TESTING()
ADD_SUBDIRECTORY (test)

