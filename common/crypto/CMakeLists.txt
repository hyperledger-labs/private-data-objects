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

CMAKE_MINIMUM_REQUIRED(VERSION 3.2 FATAL_ERROR)

# if necessary, set default names for crypto library
IF("${U_CRYPTO_LIB_NAME} " STREQUAL " ")
    SET(U_CRYPTO_LIB_NAME updo-crypto)
ENDIF()
IF("${T_CRYPTO_LIB_NAME} " STREQUAL " ")
    SET(T_CRYPTO_LIB_NAME tpdo-crypto)
ENDIF()

FILE(GLOB PROJECT_HEADERS *.h verify_ias_report/*.h)
FILE(GLOB PROJECT_SOURCES *.cpp verify_ias_report/*.cpp)

################################################################################
# Generated source
################################################################################

# this is a dependency to generate the `ias-certificates.cpp` file
SET(PROJECT_GENERATED_IAS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/verify_ias_report/ias-certificates.cpp)
SET_SOURCE_FILES_PROPERTIES(${PROJECT_GENERATED_IAS_SOURCES} PROPERTIES GENERATED TRUE)
ADD_CUSTOM_COMMAND(OUTPUT  ${PROJECT_GENERATED_IAS_SOURCES}
                     COMMAND ./build_ias_certificates_cpp.sh
                     DEPENDS verify_ias_report/ias-certificates.template verify_ias_report/build_ias_certificates_cpp.sh
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/verify_ias_report
)
ADD_CUSTOM_TARGET(generate-ias-files DEPENDS ${PROJECT_GENERATED_IAS_SOURCES})

################################################################################
# Common crypto settings
################################################################################

IF("$ENV{SGX_MODE}" STREQUAL "SIM")
    SET(IAS_CA_CERT_REQUIRED_FLAGS "")
ELSE()
    SET(IAS_CA_CERT_REQUIRED_FLAGS "-DIAS_CA_CERT_REQUIRED")
ENDIF()

SET(COMMON_CXX_FLAGS ${IAS_CA_CERT_REQUIRED_FLAGS} "-m64" "-fvisibility=hidden" "-fpie" "-fPIC" "-fstack-protector" "-std=c++11" "-Wall")

# required for: `types.h` and `error.h` in common
SET(PRIVATE_DEPS_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/.." "${CMAKE_CURRENT_SOURCE_DIR}/../packages/base64")

# required for:`sgx_error.h` in sgx-sdk
SET(PUBLIC_INCLUDE_DIRS "$ENV{SGX_SDK}/include")

################################################################################
# Trusted Crypto library
################################################################################

SET(T_INCLUDE_DIRS ${PUBLIC_INCLUDE_DIRS})
# required for: `tSgxSSL_api.h` in sgx-ssl
LIST(APPEND T_INCLUDE_DIRS "$ENV{SGX_SSL}/include")
# required for stdlibc++
LIST(APPEND T_INCLUDE_DIRS "$ENV{SGX_SDK}/include/libcxx")
# required for `sys/endian.h`
LIST(APPEND T_INCLUDE_DIRS "$ENV{SGX_SDK}/include/tlibc")

ADD_LIBRARY(${T_CRYPTO_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_GENERATED_IAS_SOURCES} ${PROJECT_SOURCES})
ADD_DEPENDENCIES(${T_CRYPTO_LIB_NAME} generate-ias-files)

TARGET_INCLUDE_DIRECTORIES(${T_CRYPTO_LIB_NAME} PRIVATE ${PRIVATE_DEPS_INCLUDE_DIRS})
TARGET_COMPILE_OPTIONS(${T_CRYPTO_LIB_NAME} PRIVATE ${COMMON_CXX_FLAGS})
TARGET_COMPILE_OPTIONS(${T_CRYPTO_LIB_NAME} PRIVATE -nostdinc)
TARGET_INCLUDE_DIRECTORIES(${T_CRYPTO_LIB_NAME} PRIVATE ${T_INCLUDE_DIRS})

################################################################################
# Untrusted Crypto library
################################################################################

SET(U_INCLUDE_DIRS ${PUBLIC_INCLUDE_DIRS})

ADD_LIBRARY(${U_CRYPTO_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_GENERATED_IAS_SOURCES} ${PROJECT_SOURCES})
ADD_DEPENDENCIES(${U_CRYPTO_LIB_NAME} generate-ias-files)

# critical flag for conditional compile in source code
TARGET_COMPILE_DEFINITIONS(${U_CRYPTO_LIB_NAME} PRIVATE "-D_UNTRUSTED_=1")

TARGET_COMPILE_OPTIONS(${U_CRYPTO_LIB_NAME} PRIVATE ${COMMON_CXX_FLAGS})
TARGET_INCLUDE_DIRECTORIES(${U_CRYPTO_LIB_NAME} PRIVATE ${PRIVATE_DEPS_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(${U_CRYPTO_LIB_NAME} PRIVATE ${U_INCLUDE_DIRS})
