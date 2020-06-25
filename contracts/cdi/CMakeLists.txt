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

IF($ENV{PDO_DEBUG_BUILD})
    SET(DEBUG_FLAGS "-Og" "-g" "-DPDO_DEBUG_BUILD=1")
    message(STATUS "Compiling in debug mode without optimizations (-Og -g)")
ELSE()
    SET(DEBUG_FLAGS "-O2" "-DPDO_DEBUG_BUILD=0")
    message(STATUS "Compiling with optimizations (-O2). To use debug flags, set the DEBUG environment variable.")
ENDIF()

SET(SGX_SDK "$ENV{SGX_SDK}")
if("${SGX_SDK} " STREQUAL " ")
    message(FATAL_ERROR "SGX_SDK environment variable not defined!")
endif()

SET(COMMON_CXX_FLAGS ${DEBUG_FLAGS} "-m64" "-fvisibility=hidden" "-fpie" "-fPIC" "-fstack-protector" "-std=c++11" "-Wall")

SET(PDO_TOP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../")
SET(U_CRYPTO_LIB_NAME updo-crypto)
SET(UNTRUSTED_LIB_NAME updo-common)

SET(COMP_REPORT_GEN gen-cdi-report)
PROJECT(${COMP_REPORT_GEN} CXX)

ADD_EXECUTABLE(${COMP_REPORT_GEN} GenCDIReport.cpp)

TARGET_INCLUDE_DIRECTORIES(${COMP_REPORT_GEN} PUBLIC ${SGX_SDK}/include)
TARGET_INCLUDE_DIRECTORIES(${COMP_REPORT_GEN} PRIVATE ${PDO_TOP_DIR}/common)
TARGET_INCLUDE_DIRECTORIES(${COMP_REPORT_GEN} PRIVATE ${PDO_TOP_DIR}/common/crypto)
TARGET_INCLUDE_DIRECTORIES(${COMP_REPORT_GEN} PRIVATE ${PDO_TOP_DIR}/common/packages/base64)
TARGET_INCLUDE_DIRECTORIES(${COMP_REPORT_GEN} PRIVATE ${PDO_TOP_DIR}/common/packages/parson)

TARGET_LINK_LIBRARIES(${COMP_REPORT_GEN} -Wl,-L,${PDO_TOP_DIR}/common/build)
TARGET_LINK_LIBRARIES(${COMP_REPORT_GEN} pthread)
TARGET_LINK_LIBRARIES(${COMP_REPORT_GEN} ${UNTRUSTED_LIB_NAME})
TARGET_LINK_LIBRARIES(${COMP_REPORT_GEN} ${U_CRYPTO_LIB_NAME} ssl crypto)
