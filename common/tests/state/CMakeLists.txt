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

# Put test artifacts under /tests subdirectory
set(TESTS_OUTPUT_DIR ${CMAKE_BINARY_DIR}/tests)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${TESTS_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${TESTS_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${TESTS_OUTPUT_DIR})

################################################################################
# Untrusted Test Application
################################################################################

SET(UNTRUSTED_TEST_NAME u_state_test)
PROJECT(${UNTRUSTED_TEST_NAME} CXX)

FILE(GLOB TEST_SOURCES untrusted/*.cpp)
ADD_EXECUTABLE(${UNTRUSTED_TEST_NAME} ${PDO_TOP_DIR}/common/c11_support.cpp ${TEST_SOURCES})

# Same compile options as untrusted library
TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_TEST_NAME} PUBLIC ${SGX_SDK}/include)
TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_TEST_NAME} PRIVATE ${PDO_TOP_DIR}/common)
TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_TEST_NAME} PRIVATE ${PDO_TOP_DIR}/common/state)
TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_TEST_NAME} PRIVATE ${PDO_TOP_DIR}/common/tests)
TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_TEST_NAME} PRIVATE ${PDO_TOP_DIR}/common/crypto)
TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_TEST_NAME} PRIVATE ${PDO_TOP_DIR}/common/packages/base64)

TARGET_COMPILE_OPTIONS(${UNTRUSTED_TEST_NAME} PRIVATE ${COMMON_CXX_FLAGS})

TARGET_COMPILE_DEFINITIONS(${UNTRUSTED_TEST_NAME} PRIVATE "-D_UNTRUSTED_=1")

# Link the untrusted test application against the untrusted library and openssl
TARGET_LINK_LIBRARIES(${UNTRUSTED_TEST_NAME} "-Wl,--start-group" ${UNTRUSTED_LIB_NAME} ${BLOCK_STORE_LIB_NAME} ${OPENSSL_LDFLAGS} -lpthread -llmdb ${U_CRYPTO_LIB_NAME} "-Wl,--end-group")

# Register this application as a test
add_test(
	NAME ${UNTRUSTED_TEST_NAME}
	COMMAND env LD_LIBRARY_PATH=${OPENSSL_LIBRARY_DIRS}:${LD_LIBRARY_PATH} ./${UNTRUSTED_TEST_NAME}
	WORKING_DIRECTORY ${TESTS_OUTPUT_DIR}
)

################################################################################
# Run the tests automatically after building
################################################################################

IF(DEFINED TEST_TARGET)
    ADD_DEPENDENCIES(${TEST_TARGET} ${UNTRUSTED_TEST_NAME})
ENDIF()
