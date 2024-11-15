# Copyright 2020 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

# pkg_check_modules needed to set OPENSSL_LDFLAGS
find_package(PkgConfig REQUIRED)
pkg_check_modules (OPENSSL REQUIRED openssl>=1.1.0g)

# Put test artifacts under /tests subdirectory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests)

##################################################################################################
## Verify Evidence test app:
## this application tests evidence from input files
##################################################################################################

SET(VERIFY_EVIDENCE_APP verify_evidence_app)

ADD_EXECUTABLE(${VERIFY_EVIDENCE_APP}
    ${VERIFY_EVIDENCE_APP}/main.cpp
    ${VERIFY_EVIDENCE_APP}/test.cpp
    common/test-utils.cpp
    )

TARGET_INCLUDE_DIRECTORIES(${VERIFY_EVIDENCE_APP} BEFORE PRIVATE "../common") # OAA common
TARGET_INCLUDE_DIRECTORIES(${VERIFY_EVIDENCE_APP} PRIVATE "../include")
TARGET_INCLUDE_DIRECTORIES(${VERIFY_EVIDENCE_APP} PRIVATE "common") # test common
TARGET_INCLUDE_DIRECTORIES(${VERIFY_EVIDENCE_APP} PRIVATE ${LOGGING_UNTRUSTED_INCLUDE_PATH})
TARGET_LINK_LIBRARIES(${VERIFY_EVIDENCE_APP} ${LOGGING_UNTRUSTED_LIB})
# Link the untrusted test application against the untrusted library and openssl
TARGET_LINK_LIBRARIES(${VERIFY_EVIDENCE_APP}
    # we assume that the libraries are located one level up
    "-L${CMAKE_CURRENT_BINARY_DIR}/.."
    "-Wl,--start-group" ${OPENSSL_LDFLAGS} "-lu-one-attestation" "-Wl,--end-group"
    )

###################################################################################################
## Attestation app:
## this application performs a sim/hw attestation from input files and writes output on file
###################################################################################################

SET(GET_ATTESTATION_APP "get_attestation_app")

ADD_SUBDIRECTORY(${GET_ATTESTATION_APP}/enclave)

INCLUDE ("${GET_ATTESTATION_APP}/enclave/CMakeVariables.txt")

# ENCLAVE_EDL is defined in the enclave subdirectory
SGX_EDGE_UNTRUSTED(${ENCLAVE_EDL} ENCLAVE_EDGE_SOURCES)

ADD_EXECUTABLE(${GET_ATTESTATION_APP}
    ${GET_ATTESTATION_APP}/app/main.cpp
    common/test-utils.cpp
    ${ENCLAVE_EDGE_SOURCES})

# Make sure the enclave builds before the test app that links it
ADD_DEPENDENCIES(${GET_ATTESTATION_APP} test_enclave)

TARGET_INCLUDE_DIRECTORIES(${GET_ATTESTATION_APP} PRIVATE "$ENV{SGX_SDK}/include")
TARGET_INCLUDE_DIRECTORIES(${GET_ATTESTATION_APP} PRIVATE "$ENV{SGX_SSL}/include")
TARGET_INCLUDE_DIRECTORIES(${GET_ATTESTATION_APP} BEFORE PRIVATE "../common") # OAA common
TARGET_INCLUDE_DIRECTORIES(${GET_ATTESTATION_APP} PRIVATE ${LOGGING_UNTRUSTED_INCLUDE_PATH})
TARGET_INCLUDE_DIRECTORIES(${GET_ATTESTATION_APP} PRIVATE "common") # test common

TARGET_LINK_LIBRARIES(${GET_ATTESTATION_APP} -Wl,-L,$ENV{SGX_SDK}/lib64)
TARGET_LINK_LIBRARIES(${GET_ATTESTATION_APP} -Wl,-L,$ENV{SGX_SSL}/lib64)
TARGET_LINK_LIBRARIES(${GET_ATTESTATION_APP}
    # we assume that the libraries are located one level up
    "-L${CMAKE_CURRENT_BINARY_DIR}/.."
    "-lu-one-attestation"
    )
TARGET_LINK_LIBRARIES(${GET_ATTESTATION_APP} ${URTS_LIBRARY_NAME} ${UAE_SERVICE_LIBRARY_NAME})
TARGET_LINK_LIBRARIES(${GET_ATTESTATION_APP} sgx_usgxssl ${SGX_EPID_LIB} sgx_dcap_ql)
TARGET_LINK_LIBRARIES(${GET_ATTESTATION_APP} ${LOGGING_UNTRUSTED_LIB})

## dcap_quoteprov necessary for dcap logging
#TARGET_LINK_LIBRARIES(${GET_ATTESTATION_APP} dcap_quoteprov)

##################################################################################################
## Verify Evidence test enclave app:
## this application tests evidence from input files
##################################################################################################

SET(VERIFY_EVIDENCE_APP_ENCLAVE verify_evidence_app_enclave)

ADD_SUBDIRECTORY(${VERIFY_EVIDENCE_APP}/enclave)

INCLUDE ("${VERIFY_EVIDENCE_APP}/enclave/CMakeVariables.txt")

# ENCLAVE_EDL is defined in the enclave subdirectory
SGX_EDGE_UNTRUSTED(${ENCLAVE_EDL} VERIFY_ENCLAVE_EDGE_SOURCES)
MESSAGE("VERIFY_ENCLAVE_EDGE_SOURCES: ${VERIFY_ENCLAVE_EDGE_SOURCES}")

ADD_EXECUTABLE(${VERIFY_EVIDENCE_APP_ENCLAVE}
    ${VERIFY_EVIDENCE_APP}/main.cpp
    ${VERIFY_EVIDENCE_APP}/test-enclave.cpp
    common/test-utils.cpp
    ${VERIFY_ENCLAVE_EDGE_SOURCES}
    )

# Make sure this app builds after get_attestation_app (because it has another enclave and build variables may conflict)
ADD_DEPENDENCIES(${VERIFY_EVIDENCE_APP_ENCLAVE} ${GET_ATTESTATION_APP})

# Make sure the enclave builds before the test app that links it
ADD_DEPENDENCIES(${VERIFY_EVIDENCE_APP_ENCLAVE} test_verify_enclave)

TARGET_INCLUDE_DIRECTORIES(${VERIFY_EVIDENCE_APP_ENCLAVE} PRIVATE "$ENV{SGX_SDK}/include")
TARGET_INCLUDE_DIRECTORIES(${VERIFY_EVIDENCE_APP_ENCLAVE} PRIVATE "$ENV{SGX_SSL}/include")
TARGET_INCLUDE_DIRECTORIES(${VERIFY_EVIDENCE_APP_ENCLAVE} BEFORE PRIVATE "../common") # OAA common
TARGET_INCLUDE_DIRECTORIES(${VERIFY_EVIDENCE_APP_ENCLAVE} PRIVATE ${LOGGING_UNTRUSTED_INCLUDE_PATH})
TARGET_INCLUDE_DIRECTORIES(${VERIFY_EVIDENCE_APP_ENCLAVE} PRIVATE "common") # test common

TARGET_INCLUDE_DIRECTORIES(${VERIFY_EVIDENCE_APP_ENCLAVE} PRIVATE "../include")

TARGET_LINK_LIBRARIES(${VERIFY_EVIDENCE_APP_ENCLAVE} -Wl,-L,$ENV{SGX_SDK}/lib64)
TARGET_LINK_LIBRARIES(${VERIFY_EVIDENCE_APP_ENCLAVE} -Wl,-L,$ENV{SGX_SSL}/lib64)
TARGET_LINK_LIBRARIES(${VERIFY_EVIDENCE_APP_ENCLAVE}
    # we assume that the libraries are located one level up
    "-L${CMAKE_CURRENT_BINARY_DIR}/.."
    "-lu-one-attestation"
    )
TARGET_LINK_LIBRARIES(${VERIFY_EVIDENCE_APP_ENCLAVE} ${URTS_LIBRARY_NAME} ${UAE_SERVICE_LIBRARY_NAME})
TARGET_LINK_LIBRARIES(${VERIFY_EVIDENCE_APP_ENCLAVE} sgx_usgxssl ${SGX_EPID_LIB} sgx_dcap_ql)
TARGET_LINK_LIBRARIES(${VERIFY_EVIDENCE_APP_ENCLAVE} ${LOGGING_UNTRUSTED_LIB})

## dcap_quoteprov necessary for logging
#TARGET_LINK_LIBRARIES(${VERIFY_EVIDENCE_APP_ENCLAVE} dcap_quoteprov)

#################################################################################
## Test
#################################################################################

SET(ATTESTED_EVIDENCE_TEST_FILE "attested_evidence_test.sh")
ADD_CUSTOM_COMMAND(
    TARGET ${GET_ATTESTATION_APP}
    PRE_BUILD
    COMMAND cp ${ATTESTED_EVIDENCE_TEST_FILE} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMAND cp ${GET_ATTESTATION_APP}/enclave/test_enclave.config.xml ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMAND mkdir -p ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/../conversion && cp -r ../conversion/* ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/../conversion
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

# Register this application as a test
ADD_TEST(
    NAME ${ATTESTED_EVIDENCE_TEST_FILE}
    COMMAND bash -c "OAA_PATH=${CMAKE_CURRENT_SOURCE_DIR}/../ ./${ATTESTED_EVIDENCE_TEST_FILE}"
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    )

