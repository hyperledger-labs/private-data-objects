# Copyright 2019 Intel Corporation
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

CMAKE_MINIMUM_REQUIRED (VERSION 3.10 FATAL_ERROR)

IF (NOT DEFINED ENV{PDO_SOURCE_ROOT})
  MESSAGE(FATAL_ERROR "PDO_SOURCE_ROOT not defined")
ENDIF()
SET(PDO_SOURCE_ROOT $ENV{PDO_SOURCE_ROOT})

LIST(APPEND CMAKE_MODULE_PATH "${PDO_SOURCE_ROOT}/build/cmake")

PROJECT(wawaka-contracts)
INCLUDE(contract-build.cmake)
INCLUDE(wawaka_common.cmake)

LIST(APPEND WASM_LIBRARIES ${WW_COMMON_LIB})
LIST(APPEND WASM_INCLUDES ${WW_COMMON_INCLUDES})

ADD_SUBDIRECTORY(mock-contract)
ADD_SUBDIRECTORY(interface-test)
ADD_SUBDIRECTORY(interpreter-test)
ADD_SUBDIRECTORY(memory-test)
ADD_SUBDIRECTORY(attestation-test)
ADD_SUBDIRECTORY(kv-test)

# -----------------------------------------------------------------
INCLUDE(Test)
ENABLE_TESTING()

ADD_UNIT_TEST(interface-test)
ADD_UNIT_TEST(interpreter-test)
ADD_UNIT_TEST(memory-test)
ADD_UNIT_TEST(mock-contract)

ADD_UNIT_TEST_WITH_SERVICES(interface-test)
# The interpreter-test appears to tickle a bug in the transaction handler
# This should be enabled to test the
# ADD_UNIT_TEST_WITH_SERVICES(interpreter-test)
ADD_UNIT_TEST_WITH_SERVICES(memory-test)
ADD_UNIT_TEST_WITH_SERVICES(mock-contract)

ADD_SYSTEM_TEST(attestation-test PARAMS -m test_data ${CMAKE_CURRENT_SOURCE_DIR}/attestation-test/scripts)
ADD_SYSTEM_TEST(interface-test)
ADD_SYSTEM_TEST(interpreter-test)
ADD_SYSTEM_TEST(kv-test)
