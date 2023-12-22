# Copyright 2018 Intel Corporation
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

# NOTE: this file is included by the common CMakeLists.txt;
# it should not be evaluated independently

# Put test artifacts under /tests subdirectory
set(TESTS_OUTPUT_DIR ${CMAKE_BINARY_DIR}/tests)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${TESTS_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${TESTS_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${TESTS_OUTPUT_DIR})

IF (BUILD_TRUSTED OR BUILD_UNTRUSTED)
  IF (NOT ${SGX_USE_SIMULATOR})
    SET(IAS_CA_CERT_REQUIRED_FLAGS "IAS_CA_CERT_REQUIRED=1")
  ENDIF()
ENDIF()

SET(CRYPTO_TEST_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/testCrypto.cpp ${CMAKE_CURRENT_SOURCE_DIR}/test_sig.cpp)
SET(CRYPTO_TEST_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR})

################################################################################
# Untrusted Test Application
################################################################################
IF (BUILD_UNTRUSTED)
  SET(UNTRUSTED_TEST_NAME utest)
  PROJECT(${UNTRUSTED_TEST_NAME} CXX)

  ADD_EXECUTABLE(${UNTRUSTED_TEST_NAME} untrusted/TestUntrusted.cpp ${CRYPTO_TEST_SOURCE})
  SGX_PREPARE_UNTRUSTED(${UNTRUSTED_TEST_NAME})

  # Same compile options as untrusted library
  TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_TEST_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

  TARGET_COMPILE_DEFINITIONS(${UNTRUSTED_TEST_NAME} PRIVATE ${IAS_CA_CERT_REQUIRED_FLAGS})
  TARGET_COMPILE_DEFINITIONS(${UNTRUSTED_TEST_NAME} PRIVATE "_UNTRUSTED_=1")

  # Link the untrusted test application against the untrusted library and openssl
  TARGET_LINK_LIBRARIES(${UNTRUSTED_TEST_NAME} "-Wl,--start-group")
  TARGET_LINK_LIBRARIES(${UNTRUSTED_TEST_NAME} ${COMMON_UNTRUSTED_LIBS})
  TARGET_LINK_LIBRARIES(${UNTRUSTED_TEST_NAME} ${OPENSSL_LDFLAGS})
  TARGET_LINK_LIBRARIES(${UNTRUSTED_TEST_NAME} "-Wl,--end-group")

  # Register this application as a test
  ADD_TEST(
    NAME ${UNTRUSTED_TEST_NAME}
    COMMAND env LD_LIBRARY_PATH=${OPENSSL_LIBRARY_DIRS}:${LD_LIBRARY_PATH} ./${UNTRUSTED_TEST_NAME}
    WORKING_DIRECTORY ${TESTS_OUTPUT_DIR}
  )
ENDIF()

################################################################################
# Trusted Test Application
################################################################################
IF (BUILD_TRUSTED)
  ADD_SUBDIRECTORY(trusted/enclave)

  SET(TRUSTED_TEST_NAME ttest)
  PROJECT(${TRUSTED_TEST_NAME} C CXX)

  # ENCLAVE_EDL is defined in the enclave subdirectory
  SGX_EDGE_UNTRUSTED(${ENCLAVE_EDL} ENCLAVE_EDGE_SOURCES)

  ADD_EXECUTABLE(${TRUSTED_TEST_NAME} trusted/app/TestApp.cpp ${ENCLAVE_EDGE_SOURCES})
  SGX_PREPARE_UNTRUSTED(${TRUSTED_TEST_NAME})

  TARGET_COMPILE_DEFINITIONS(${TRUSTED_TEST_NAME} PRIVATE ${IAS_CA_CERT_REQUIRED_FLAGS})

  TARGET_INCLUDE_DIRECTORIES(${TRUSTED_TEST_NAME} PRIVATE ${CRYPTO_TEST_INCLUDE})

  TARGET_LINK_LIBRARIES(${TRUSTED_TEST_NAME} "-Wl,--start-group")
  TARGET_LINK_LIBRARIES(${TRUSTED_TEST_NAME} ${COMMON_UNTRUSTED_LIBS})
  TARGET_LINK_LIBRARIES(${TRUSTED_TEST_NAME} "-Wl,--end-group")

  # Pick up this library for u_sgxssl_ftime
  TARGET_LINK_LIBRARIES(${TRUSTED_TEST_NAME} sgx_usgxssl)

  ADD_DEPENDENCIES(${TRUSTED_TEST_NAME} TestEnclave)

  # Register this application as a test
  ADD_TEST(
    NAME ${TRUSTED_TEST_NAME}
    COMMAND ./${TRUSTED_TEST_NAME}
    WORKING_DIRECTORY ${TESTS_OUTPUT_DIR}
  )

ENDIF()
